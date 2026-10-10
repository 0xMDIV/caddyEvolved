package supervisor

import (
	"bufio"
	"io"
	"os"
	"strings"
)

// tailLines keeps the last n lines of r without loading the whole log.
// caddy logs a busy proxy, so an installer must not read it all into memory.
func tailLines(r io.Reader, n int) ([]string, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	window := make([]string, 0, n)
	var err error
	for sc.Scan() {
		line := sc.Text()
		if len(window) == n {
			copy(window, window[1:])
			window[n-1] = line
		} else {
			window = append(window, line)
		}
	}
	if sc.Err() != nil {
		err = sc.Err()
	}
	return window, err
}

// TailFile reads the end of a file by path.
func TailFile(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()
	return tailLines(f, n)
}

// Join renders log lines for JSON responses.
func Join(lines []string) string { return strings.Join(lines, "\n") }
