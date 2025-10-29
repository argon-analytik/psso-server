package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrDeviceNotFound = errors.New("device not found")
	ErrNonceNotFound  = errors.New("nonce not found")
	ErrNonceExpired   = errors.New("nonce expired")
	ErrNonceMismatch  = errors.New("nonce does not match device")
	ErrNonceUsed      = errors.New("nonce already consumed")
)

type Device struct {
	DeviceID         string    `json:"device_id"`
	UDID             string    `json:"udid,omitempty"`
	SerialNumber     string    `json:"serial_number,omitempty"`
	SigningKeyPEM    string    `json:"signing_key_pem"`
	SigningKeyID     string    `json:"signing_key_id"`
	EncryptionKeyPEM string    `json:"encryption_key_pem"`
	EncryptionKeyID  string    `json:"encryption_key_id"`
	KeyVersion       string    `json:"key_version"`
	RegisteredAt     time.Time `json:"registered_at"`
	LastSeen         time.Time `json:"last_seen"`
}

type Nonce struct {
	Value     string    `json:"value"`
	DeviceID  string    `json:"device_id,omitempty"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
	Used      bool      `json:"used"`
	UsedAt    time.Time `json:"used_at,omitempty"`
}

type Store interface {
	UpsertDevice(ctx context.Context, device Device) (Device, error)
	GetDevice(ctx context.Context, deviceID string) (Device, error)
	SaveNonce(ctx context.Context, nonce Nonce) error
	ConsumeNonce(ctx context.Context, value string, deviceID string) (Nonce, error)
}

type FSStore struct {
	root        string
	devicesPath string
	noncesPath  string
	mu          sync.Mutex
}

func NewFSStore(root, devicesPath, noncesPath string) (*FSStore, error) {
	if root == "" {
		return nil, fmt.Errorf("state root is empty")
	}
	if devicesPath == "" {
		devicesPath = filepath.Join(root, "devices")
	}
	if noncesPath == "" {
		noncesPath = filepath.Join(root, "nonces")
	}
	for _, dir := range []string{root, devicesPath, noncesPath} {
		if err := os.MkdirAll(dir, 0o750); err != nil {
			return nil, fmt.Errorf("create state dir %s: %w", dir, err)
		}
	}
	return &FSStore{root: root, devicesPath: devicesPath, noncesPath: noncesPath}, nil
}

func (s *FSStore) UpsertDevice(ctx context.Context, device Device) (Device, error) {
	if device.DeviceID == "" {
		return Device{}, fmt.Errorf("device_id is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	existing, err := s.loadDevice(device.DeviceID)
	if err == nil {
		device.RegisteredAt = existing.RegisteredAt
		if device.RegisteredAt.IsZero() {
			device.RegisteredAt = now
		}
	} else {
		device.RegisteredAt = now
	}
	device.LastSeen = now

	filename := filepath.Join(s.devicesPath, safeFileName(device.DeviceID)+".json")
	data, err := json.MarshalIndent(device, "", "  ")
	if err != nil {
		return Device{}, fmt.Errorf("encode device: %w", err)
	}
	if err := os.WriteFile(filename, data, 0o640); err != nil {
		return Device{}, fmt.Errorf("write device: %w", err)
	}
	return device, nil
}

func (s *FSStore) GetDevice(ctx context.Context, deviceID string) (Device, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadDevice(deviceID)
}

func (s *FSStore) SaveNonce(ctx context.Context, nonce Nonce) error {
	if nonce.Value == "" {
		return fmt.Errorf("nonce value required")
	}
	if nonce.ExpiresAt.IsZero() {
		return fmt.Errorf("expires_at required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	filename := filepath.Join(s.noncesPath, safeFileName(nonce.Value)+".json")
	if _, err := os.Stat(filename); err == nil {
		return ErrNonceUsed
	}
	nonce.CreatedAt = time.Now().UTC()
	nonce.Used = false
	nonce.UsedAt = time.Time{}
	return s.writeNonceLocked(filename, nonce)
}

func (s *FSStore) ConsumeNonce(ctx context.Context, value, deviceID string) (Nonce, error) {
	if value == "" {
		return Nonce{}, fmt.Errorf("nonce required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	filename := filepath.Join(s.noncesPath, safeFileName(value)+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Nonce{}, ErrNonceNotFound
		}
		return Nonce{}, fmt.Errorf("read nonce: %w", err)
	}

	var stored Nonce
	if err := json.Unmarshal(data, &stored); err != nil {
		return Nonce{}, fmt.Errorf("decode nonce: %w", err)
	}

	if stored.Used {
		return Nonce{}, ErrNonceUsed
	}

	if !stored.ExpiresAt.IsZero() && time.Now().UTC().After(stored.ExpiresAt) {
		_ = os.Remove(filename)
		return Nonce{}, ErrNonceExpired
	}

	if stored.DeviceID != "" && deviceID != "" && !strings.EqualFold(stored.DeviceID, deviceID) {
		return Nonce{}, ErrNonceMismatch
	}

	stored.Used = true
	stored.UsedAt = time.Now().UTC()
	if err := s.writeNonceLocked(filename, stored); err != nil {
		return Nonce{}, err
	}

	return stored, nil
}

func (s *FSStore) writeNonceLocked(filename string, nonce Nonce) error {
	data, err := json.MarshalIndent(nonce, "", "  ")
	if err != nil {
		return fmt.Errorf("encode nonce: %w", err)
	}
	if err := os.WriteFile(filename, data, 0o640); err != nil {
		return fmt.Errorf("write nonce: %w", err)
	}
	return nil
}

func (s *FSStore) loadDevice(deviceID string) (Device, error) {
	if deviceID == "" {
		return Device{}, ErrDeviceNotFound
	}
	filename := filepath.Join(s.devicesPath, safeFileName(deviceID)+".json")
	data, err := os.ReadFile(filename)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Device{}, ErrDeviceNotFound
		}
		return Device{}, fmt.Errorf("read device: %w", err)
	}
	var device Device
	if err := json.Unmarshal(data, &device); err != nil {
		return Device{}, fmt.Errorf("decode device: %w", err)
	}
	return device, nil
}

func safeFileName(input string) string {
	trimmed := strings.TrimSpace(input)
	if trimmed == "" {
		return "_"
	}
	return base64.RawURLEncoding.EncodeToString([]byte(trimmed))
}
