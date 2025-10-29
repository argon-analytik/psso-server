package handlers

import "testing"

func TestAcceptsPSSOResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		header string
		want   bool
	}{
		{
			name:   "login response",
			header: "application/platformsso-login-response+jwt",
			want:   true,
		},
		{
			name:   "fallback jwt",
			header: "application/jwt",
			want:   true,
		},
		{
			name:   "weighted list",
			header: "application/json;q=0.8, application/platformsso-login-response+jwt;q=0.5",
			want:   true,
		},
		{
			name:   "unsupported",
			header: "application/json",
			want:   false,
		},
		{
			name:   "empty",
			header: "",
			want:   false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := acceptsPSSOResponse(tt.header); got != tt.want {
				t.Fatalf("expected %v got %v", tt.want, got)
			}
		})
	}
}
