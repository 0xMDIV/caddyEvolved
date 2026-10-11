// Package backup saves and restores the configuration: caddyEvolved's own
// files, the Caddyfile with every site snippet and, on request, caddy's
// certificates and ACME accounts. An archive is a tar.gz with a manifest; with
// a passphrase it is sealed with AES-256-GCM (key from PBKDF2-SHA256).
package backup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/aes"
	"crypto/cipher"
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/user"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"caddyevolved/internal/config"
)

// Format is bumped when the archive layout changes incompatibly.
const Format = 1

const manifestName = "manifest.json"

// Archive members live under one prefix per source tree, so a restore maps
// them back onto whatever layout (live system or --root prefix) it runs in.
const (
	prefixEtc       = "caddyevolved-etc/"
	prefixCaddyEtc  = "caddy-etc/"
	prefixCaddyData = "caddy-data/"
)

// Manifest describes an archive.
type Manifest struct {
	Format    int       `json:"format"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"createdAt"`
	Host      string    `json:"host"`
	Sites     int       `json:"sites"`
	Files     int       `json:"files"`
	Bytes     int64     `json:"bytes"`
	Secrets   bool      `json:"secrets"`
	Certs     bool      `json:"certs"`
	Encrypted bool      `json:"encrypted"`
	Reason    string    `json:"reason,omitempty"`
}

// Options select what goes into an archive.
type Options struct {
	// Certs adds caddy's storage (certificates, keys, ACME accounts, local CA).
	Certs bool
	// Passphrase seals the archive; empty leaves it plain.
	Passphrase string
	// Version and Reason end up in the manifest.
	Version string
	Reason  string
}

// Create writes an archive of paths to w.
func Create(paths config.Paths, w io.Writer, o Options) (Manifest, error) {
	host, _ := os.Hostname()
	m := Manifest{Format: Format, Version: o.Version, CreatedAt: time.Now().UTC(), Host: host, Certs: o.Certs, Encrypted: o.Passphrase != "", Reason: o.Reason}

	var payload bytes.Buffer
	gz := gzip.NewWriter(&payload)
	tw := tar.NewWriter(gz)

	add := func(prefix, root string, skip func(rel string) bool) error {
		return filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) && p == root {
					return fs.SkipDir
				}
				return err
			}
			rel, _ := filepath.Rel(root, p)
			rel = filepath.ToSlash(rel)
			if rel == "." {
				return nil
			}
			if skip != nil && skip(rel) {
				if d.IsDir() {
					return fs.SkipDir
				}
				return nil
			}
			if !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil {
				return err
			}
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			hdr := &tar.Header{Name: prefix + rel, Mode: int64(info.Mode().Perm()), Size: int64(len(data)), ModTime: info.ModTime(), Typeflag: tar.TypeReg}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			if _, err := tw.Write(data); err != nil {
				return err
			}
			m.Files++
			m.Bytes += int64(len(data))
			if prefix == prefixEtc && (rel == "env" || rel == "auth.json") {
				m.Secrets = true
			}
			return nil
		})
	}

	if err := add(prefixEtc, paths.Etc, nil); err != nil {
		return m, fmt.Errorf("%s: %w", paths.Etc, err)
	}
	// Only what defines the configuration: the Caddyfile and the site
	// snippets, not editor leftovers or the .prev copies.
	if err := add(prefixCaddyEtc, paths.CaddyEtc, func(rel string) bool {
		return !(rel == "Caddyfile" || rel == "sites" || strings.HasPrefix(rel, "sites/"))
	}); err != nil {
		return m, fmt.Errorf("%s: %w", paths.CaddyEtc, err)
	}
	if o.Certs {
		// Locks and the OCSP cache are rebuilt by caddy on its own.
		if err := add(prefixCaddyData, paths.CaddyStorage, func(rel string) bool {
			return rel == "locks" || strings.HasPrefix(rel, "locks/") || rel == "ocsp" || strings.HasPrefix(rel, "ocsp/")
		}); err != nil {
			return m, fmt.Errorf("%s: %w", paths.CaddyStorage, err)
		}
	}
	m.Sites = countSites(paths.SitesFile)

	mdata, _ := json.MarshalIndent(m, "", "  ")
	if err := tw.WriteHeader(&tar.Header{Name: manifestName, Mode: 0o600, Size: int64(len(mdata)), ModTime: m.CreatedAt, Typeflag: tar.TypeReg}); err != nil {
		return m, err
	}
	if _, err := tw.Write(mdata); err != nil {
		return m, err
	}
	if err := tw.Close(); err != nil {
		return m, err
	}
	if err := gz.Close(); err != nil {
		return m, err
	}

	out := payload.Bytes()
	if o.Passphrase != "" {
		sealed, err := seal(out, o.Passphrase)
		if err != nil {
			return m, err
		}
		out = sealed
	}
	_, err := w.Write(out)
	return m, err
}

func countSites(file string) int {
	data, err := os.ReadFile(file)
	if err != nil {
		return 0
	}
	var doc struct {
		Sites []json.RawMessage `json:"sites"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return 0
	}
	return len(doc.Sites)
}

// ---- reading ---------------------------------------------------------------

// ErrPassphrase means the archive is encrypted and the passphrase is missing
// or wrong.
var ErrPassphrase = errors.New("Backup ist verschlüsselt – Passwort fehlt oder ist falsch")

// IsEncrypted reports a sealed archive.
func IsEncrypted(data []byte) bool { return bytes.HasPrefix(data, magic) }

type member struct {
	name string
	mode os.FileMode
	data []byte
}

// open decrypts if needed and reads every member.
func open(data []byte, passphrase string) (Manifest, []member, error) {
	if IsEncrypted(data) {
		plain, err := unseal(data, passphrase)
		if err != nil {
			return Manifest{}, nil, err
		}
		data = plain
	}
	gz, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return Manifest{}, nil, errors.New("keine caddyEvolved-Sicherung (kein tar.gz)")
	}
	tr := tar.NewReader(gz)
	var m Manifest
	var members []member
	var total int64
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return m, nil, fmt.Errorf("Archiv beschädigt: %w", err)
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		total += hdr.Size
		if total > 512<<20 {
			return m, nil, errors.New("Archiv zu groß")
		}
		body, err := io.ReadAll(io.LimitReader(tr, hdr.Size))
		if err != nil {
			return m, nil, err
		}
		if hdr.Name == manifestName {
			if err := json.Unmarshal(body, &m); err != nil {
				return m, nil, fmt.Errorf("Manifest: %w", err)
			}
			continue
		}
		members = append(members, member{name: hdr.Name, mode: os.FileMode(hdr.Mode).Perm(), data: body})
	}
	if m.Format == 0 {
		return m, nil, errors.New("keine caddyEvolved-Sicherung (Manifest fehlt)")
	}
	if m.Format > Format {
		return m, nil, fmt.Errorf("Sicherung stammt aus einer neueren Version (Format %d) – erst caddyEvolved aktualisieren", m.Format)
	}
	return m, members, nil
}

// Inspect reads the manifest and lists the members.
func Inspect(data []byte, passphrase string) (Manifest, []string, error) {
	m, members, err := open(data, passphrase)
	if err != nil {
		return m, nil, err
	}
	names := make([]string, 0, len(members))
	for _, mb := range members {
		names = append(names, mb.name)
	}
	m.Encrypted = IsEncrypted(data)
	return m, names, nil
}

// RestoreOptions narrow what a restore writes.
type RestoreOptions struct {
	// Certs restores caddy's storage when the archive contains it.
	Certs bool
}

// Restore writes the archive's files back. Site snippets not in the archive
// are removed, so the site set matches the backup exactly. The caller takes a
// safety backup first and validates/reloads afterwards.
func Restore(paths config.Paths, data []byte, passphrase string, o RestoreOptions) (Manifest, error) {
	m, members, err := open(data, passphrase)
	if err != nil {
		return m, err
	}
	type target struct {
		path  string
		mode  os.FileMode
		data  []byte
		caddy bool
	}
	var targets []target
	keepSnippets := map[string]bool{}
	for _, mb := range members {
		var base, rel string
		caddyOwned := false
		switch {
		case strings.HasPrefix(mb.name, prefixEtc):
			base, rel = paths.Etc, strings.TrimPrefix(mb.name, prefixEtc)
		case strings.HasPrefix(mb.name, prefixCaddyEtc):
			base, rel = paths.CaddyEtc, strings.TrimPrefix(mb.name, prefixCaddyEtc)
			if strings.HasPrefix(rel, "sites/") {
				keepSnippets[path.Base(rel)] = true
			}
		case strings.HasPrefix(mb.name, prefixCaddyData):
			if !o.Certs {
				continue
			}
			base, rel, caddyOwned = paths.CaddyStorage, strings.TrimPrefix(mb.name, prefixCaddyData), true
		default:
			continue
		}
		clean := path.Clean("/" + rel)
		if clean == "/" || strings.Contains(rel, "..") {
			return m, fmt.Errorf("unsicherer Pfad im Archiv: %s", mb.name)
		}
		targets = append(targets, target{path: filepath.Join(base, filepath.FromSlash(clean)), mode: mb.mode, data: mb.data, caddy: caddyOwned})
	}

	uid, gid := caddyIDs()
	for _, t := range targets {
		dir := filepath.Dir(t.path)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return m, err
		}
		mode := t.mode
		if mode == 0 {
			mode = 0o600
		}
		tmp := t.path + ".restore-tmp"
		if err := os.WriteFile(tmp, t.data, mode); err != nil {
			return m, err
		}
		if err := os.Chmod(tmp, mode); err != nil {
			return m, err
		}
		if t.caddy && uid >= 0 {
			_ = os.Chown(tmp, uid, gid)
			_ = chownUp(dir, paths.CaddyData, uid, gid)
		}
		if err := os.Rename(tmp, t.path); err != nil {
			os.Remove(tmp)
			return m, err
		}
	}

	// Sites that did not exist at backup time go away.
	if entries, err := os.ReadDir(paths.SitesDir); err == nil {
		for _, e := range entries {
			if strings.HasSuffix(e.Name(), ".caddy") && !keepSnippets[e.Name()] {
				_ = os.Remove(filepath.Join(paths.SitesDir, e.Name()))
			}
		}
	}
	return m, nil
}

// caddyIDs looks up the service user that owns caddy's storage.
func caddyIDs() (int, int) {
	u, err := user.Lookup("caddy")
	if err != nil {
		return -1, -1
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	return uid, gid
}

// chownUp hands every directory from dir up to (excluding) stop to caddy.
func chownUp(dir, stop string, uid, gid int) error {
	for d := dir; strings.HasPrefix(d, stop) && d != stop && d != "/"; d = filepath.Dir(d) {
		if err := os.Chown(d, uid, gid); err != nil {
			return err
		}
	}
	return nil
}

// ---- encryption ------------------------------------------------------------

var magic = []byte("CEVBAK1\n")

const kdfRounds = 600_000

func deriveKey(passphrase string, salt []byte) ([]byte, error) {
	return pbkdf2.Key(sha256.New, passphrase, salt, kdfRounds, 32)
}

func seal(plain []byte, passphrase string) ([]byte, error) {
	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		return nil, err
	}
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	out := append(append(append([]byte{}, magic...), salt...), nonce...)
	return gcm.Seal(out, nonce, plain, magic), nil
}

func unseal(data []byte, passphrase string) ([]byte, error) {
	if passphrase == "" {
		return nil, ErrPassphrase
	}
	rest := data[len(magic):]
	if len(rest) < 16+12+16 {
		return nil, errors.New("verschlüsseltes Backup ist zu kurz")
	}
	salt, rest := rest[:16], rest[16:]
	key, err := deriveKey(passphrase, salt)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce, ct := rest[:gcm.NonceSize()], rest[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ct, magic)
	if err != nil {
		return nil, ErrPassphrase
	}
	return plain, nil
}
