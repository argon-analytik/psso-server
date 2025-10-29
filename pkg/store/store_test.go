package store

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestConsumeNonceMarksUsed(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	s, err := NewFSStore(root, "", "")
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}

	nonce := Nonce{Value: "nonce-1", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.SaveNonce(context.Background(), nonce); err != nil {
		t.Fatalf("SaveNonce: %v", err)
	}

	consumed, err := s.ConsumeNonce(context.Background(), nonce.Value, "")
	if err != nil {
		t.Fatalf("ConsumeNonce: %v", err)
	}
	if !consumed.Used {
		t.Fatalf("expected Used flag to be true: %+v", consumed)
	}
	if consumed.UsedAt.IsZero() {
		t.Fatalf("expected UsedAt to be set")
	}

	filename := filepath.Join(root, "nonces", safeFileName(nonce.Value)+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	var stored Nonce
	if err := json.Unmarshal(data, &stored); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if !stored.Used {
		t.Fatalf("expected stored nonce to remain marked as used")
	}

	if _, err := s.ConsumeNonce(context.Background(), nonce.Value, ""); !errors.Is(err, ErrNonceUsed) {
		t.Fatalf("expected ErrNonceUsed, got %v", err)
	}
}

func TestConsumeNonceExpiryAndMismatch(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	s, err := NewFSStore(root, "", "")
	if err != nil {
		t.Fatalf("NewFSStore: %v", err)
	}

	expired := Nonce{Value: "expired", ExpiresAt: time.Now().Add(-time.Second)}
	if err := s.SaveNonce(context.Background(), expired); err != nil {
		t.Fatalf("SaveNonce expired: %v", err)
	}
	if _, err := s.ConsumeNonce(context.Background(), expired.Value, ""); !errors.Is(err, ErrNonceExpired) {
		t.Fatalf("expected ErrNonceExpired, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "nonces", safeFileName(expired.Value)+".json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected expired nonce file to be removed, got %v", err)
	}

	bound := Nonce{Value: "bound", DeviceID: "A", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.SaveNonce(context.Background(), bound); err != nil {
		t.Fatalf("SaveNonce bound: %v", err)
	}
	if _, err := s.ConsumeNonce(context.Background(), bound.Value, "B"); !errors.Is(err, ErrNonceMismatch) {
		t.Fatalf("expected ErrNonceMismatch, got %v", err)
	}
	if _, err := s.ConsumeNonce(context.Background(), bound.Value, "A"); err != nil {
		t.Fatalf("expected successful consume after mismatch, got %v", err)
	}
}
