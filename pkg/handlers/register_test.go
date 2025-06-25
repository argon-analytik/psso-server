package handlers

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/twocanoes/psso-server/pkg/constants"
)

func TestRegisterCreatesKeyFiles(t *testing.T) {
	tempDir := t.TempDir()
	constants.KeyPath = filepath.Join(tempDir, "keys")
	constants.DeviceFilePath = filepath.Join(tempDir, "devices")

	signKeyIDBytes := []byte{1, 2, 3, 4}
	encKeyIDBytes := []byte{4, 5, 6, 7}

	reg := PSSORegistration{
		DeviceUUID:          "device1",
		DeviceSigningKey:    "sign",
		DeviceEncryptionKey: "enc",
		SignKeyID:           base64.StdEncoding.EncodeToString(signKeyIDBytes),
		EncKeyID:            base64.StdEncoding.EncodeToString(encKeyIDBytes),
	}

	body, err := json.Marshal(reg)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/register", bytes.NewReader(body))
	w := httptest.NewRecorder()

	Register()(w, req)

	signHex := "01020304"
	encHex := "04050607"

	signFile := filepath.Join(constants.KeyPath, signHex+".json")
	encFile := filepath.Join(constants.KeyPath, encHex+".json")

	if _, err := os.Stat(signFile); err != nil {
		t.Fatalf("signing key file not found: %v", err)
	}
	if _, err := os.Stat(encFile); err != nil {
		t.Fatalf("encryption key file not found: %v", err)
	}

	if _, err := os.Stat(encFile + ".json"); err == nil {
		t.Fatalf("encryption key file has extra extension")
	}
}
