package supervisor

import (
	"bufio"
	"io"
	"strings"
)

// readEnvLines turns a systemd EnvironmentFile into os/exec Env entries.
//
// systemd writes KEY=VALUE with optional quoting and comments; caddy needs the
// same values as real environment variables when systemd is not available, so
// this is a parser for the subset we ourselves write.
func readEnvLines(r io.Reader) ([]string, error) {
	var out []string
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 {
			if (value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'') {
				value = strings.ReplaceAll(value[1:len(value)-1], `\"`, `"`)
			}
		}
		out = append(out, key+"="+value)
	}
	return out, sc.Err()
}
