package api

import (
	"testing"

	"caddyevolved/internal/geo"
)

func TestGeoForSkipsUnknownAndDuplicates(t *testing.T) {
	s := &Server{Geo: geo.New(func() (string, string) { return "", "" })}
	if m := s.geoFor([]string{"1.1.1.1", "1.1.1.1", ""}); len(m) != 0 {
		t.Fatalf("ohne Datenbank: %v", m)
	}
	var nilServer Server
	if m := nilServer.geoFor([]string{"1.1.1.1"}); m == nil || len(m) != 0 {
		t.Fatalf("ohne Resolver: %v", m)
	}
}
