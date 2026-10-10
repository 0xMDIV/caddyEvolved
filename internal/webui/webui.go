// Package webui serves the compiled single-page app out of the binary.
//
// CADDYFORGE_UI_DIST overrides the embedded copy with a directory, which is how
// `npm run dev` output gets tested without rebuilding Go.
package webui

import (
	"embed"
	"io/fs"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
)

//go:embed all:dist
var embedded embed.FS

// DevDist is the override directory, empty unless the env var is set.
var DevDist = os.Getenv("CADDYFORGE_UI_DIST")

// Handler returns the SPA filesystem as an http.Handler.
func Handler() http.Handler {
	if DevDist != "" {
		if st, err := os.Stat(DevDist); err == nil && st.IsDir() {
			log.Printf("webui: ausgeliefert aus %s (CADDYFORGE_UI_DIST)", DevDist)
			return spa(os.DirFS(DevDist).(fs.FS))
		}
		log.Printf("webui: CADDYFORGE_UI_DIST=%s nicht lesbar, nutze eingebettete Assets", DevDist)
	}
	sub, err := fs.Sub(embedded, "dist")
	if err != nil {
		// An unreachable branch: the embed directive guarantees dist exists.
		panic("webui: embeddede Assets fehlen: " + err.Error())
	}
	return spa(sub)
}

// spa serves static files and falls back to index.html for client-side routes,
// so a reload on /config works.
func spa(fsys fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(fsys))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upath := path.Clean(r.URL.Path)
		if upath == "/" {
			serveIndex(w, r, fsys, fileServer)
			return
		}
		name := strings.TrimPrefix(upath, "/")
		if f, err := fs.Stat(fsys, name); err != nil || f.IsDir() {
			if !strings.Contains(path.Base(name), ".") {
				// A route, not a file: hand it to the SPA.
				serveIndex(w, r, fsys, fileServer)
				return
			}
			http.NotFound(w, r)
			return
		}
		if strings.HasPrefix(name, "assets/") {
			// Vite emits content hashes, so these are safe to cache forever.
			w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
		}
		fileServer.ServeHTTP(w, r)
	})
}

func serveIndex(w http.ResponseWriter, r *http.Request, fsys fs.FS, fileServer http.Handler) {
	if _, err := fs.Stat(fsys, "index.html"); err != nil {
		http.Error(w, "WebUI ist nicht eingebettet – `npm run build` im Ordner ui/ und dann erneut bauen", http.StatusServiceUnavailable)
		return
	}
	r2 := r.Clone(r.Context())
	r2.URL.Path = "/"
	fileServer.ServeHTTP(w, r2)
}
