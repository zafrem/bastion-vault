package config

import (
	"strings"
	"testing"
)

func TestValidateAuth(t *testing.T) {
	good := strings.Repeat("k", 32)
	cases := []struct {
		name    string
		auth    AuthConfig
		wantErr bool
	}{
		{"strong secret", AuthConfig{JWTSecret: good, JWTAlgorithm: "HS256"}, false},
		{"empty secret", AuthConfig{JWTAlgorithm: "HS256"}, true},
		{"shipped placeholder", AuthConfig{JWTSecret: "change-me-in-production", JWTAlgorithm: "HS256"}, true},
		{"too short", AuthConfig{JWTSecret: "short", JWTAlgorithm: "HS256"}, true},
		{"skip_auth bypasses check", AuthConfig{SkipAuth: true}, false},
	}
	for _, tc := range cases {
		err := (&Config{Auth: tc.auth}).ValidateAuth()
		if (err != nil) != tc.wantErr {
			t.Errorf("%s: err=%v, wantErr=%v", tc.name, err, tc.wantErr)
		}
	}
}
