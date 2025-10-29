package handlers

import (
	"net/http"
	"testing"
)

func TestNegotiateTokenContentType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header http.Header
		want   string
		ok     bool
	}{
		{
			name:   "no accept defaults to login",
			header: http.Header{},
			want:   tokenAcceptLoginResponse,
			ok:     true,
		},
		{
			name: "explicit key response",
			header: http.Header{
				"Accept": {"application/platformsso-key-response+jwt"},
			},
			want: tokenAcceptKeyResponse,
			ok:   true,
		},
		{
			name: "explicit login response",
			header: http.Header{
				"Accept": {"application/platformsso-login-response+jwt"},
			},
			want: tokenAcceptLoginResponse,
			ok:   true,
		},
		{
			name: "wildcard fallback",
			header: http.Header{
				"Accept": {"*/*"},
			},
			want: tokenAcceptLoginResponse,
			ok:   true,
		},
		{
			name: "weighted values",
			header: http.Header{
				"Accept": {"application/json;q=0.8, application/platformsso-key-response+jwt;q=0.5"},
			},
			want: tokenAcceptKeyResponse,
			ok:   true,
		},
		{
			name: "unsupported type",
			header: http.Header{
				"Accept": {"application/json"},
			},
			ok: false,
		},
		{
			name: "multiple headers",
			header: http.Header{
				"Accept": {"application/json", "application/platformsso-login-response+jwt"},
			},
			want: tokenAcceptLoginResponse,
			ok:   true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, ok := negotiateTokenContentType(tt.header)
			if ok != tt.ok {
				t.Fatalf("expected ok=%v got %v", tt.ok, ok)
			}
			if ok && got != tt.want {
				t.Fatalf("expected %q got %q", tt.want, got)
			}
		})
	}
}
