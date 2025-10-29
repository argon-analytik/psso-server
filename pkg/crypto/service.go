package crypto

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"strings"

	jose "github.com/go-jose/go-jose/v3"
)

var (
	ErrNoDecryptionKey = errors.New("no server decryption key configured")
	ErrUnsupportedKey  = errors.New("unsupported key type")
)

type Service struct {
	signingKey       interface{}
	signingPublicKey interface{}
	signingAlg       jose.SignatureAlgorithm
	signingKID       string

	encryptionPrivate interface{}
	encryptionPublic  interface{}
}

func NewService(signingKeyPath, signingKID, encryptionKeyPath string) (*Service, error) {
	if signingKeyPath == "" {
		return nil, fmt.Errorf("server signing key path not configured")
	}

	signingKey, err := loadPrivateKey(signingKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load signing key: %w", err)
	}

	signingAlg, err := signatureAlgorithmForKey(signingKey)
	if err != nil {
		return nil, err
	}

	signingPublic, err := publicFromPrivate(signingKey)
	if err != nil {
		return nil, fmt.Errorf("derive signing public key: %w", err)
	}

	svc := &Service{
		signingKey:       signingKey,
		signingPublicKey: signingPublic,
		signingAlg:       signingAlg,
		signingKID:       signingKID,
	}

	if encryptionKeyPath != "" {
		encKey, err := loadPrivateKey(encryptionKeyPath)
		if err != nil {
			return nil, fmt.Errorf("load encryption key: %w", err)
		}
		encPublic, err := publicFromPrivate(encKey)
		if err != nil {
			return nil, fmt.Errorf("derive encryption public key: %w", err)
		}
		svc.encryptionPrivate = encKey
		svc.encryptionPublic = encPublic
	}

	return svc, nil
}

func (s *Service) SigningKID() string {
	return s.signingKID
}

func (s *Service) SigningAlgorithm() jose.SignatureAlgorithm {
	return s.signingAlg
}

func (s *Service) SignJWT(claims interface{}) (string, error) {
	if s.signingKey == nil {
		return nilStringErr("signing key not loaded")
	}
	opts := (&jose.SignerOptions{}).WithType("JWT")
	if s.signingKID != "" {
		opts.WithHeader("kid", s.signingKID)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: s.signingAlg, Key: s.signingKey}, opts)
	if err != nil {
		return "", fmt.Errorf("new signer: %w", err)
	}

	payload, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("marshal claims: %w", err)
	}

	jws, err := signer.Sign(payload)
	if err != nil {
		return "", fmt.Errorf("sign jwt: %w", err)
	}
	return jws.CompactSerialize()
}

func (s *Service) EncryptForDevice(signedJWT string, devicePublicKey interface{}, kid string) (string, error) {
	if devicePublicKey == nil {
		return "", fmt.Errorf("device public key is required")
	}
	rsaKey, ok := devicePublicKey.(*rsa.PublicKey)
	if !ok {
		return "", fmt.Errorf("device encryption key must be RSA public key")
	}

	recipient := jose.Recipient{
		Algorithm: jose.RSA_OAEP_256,
		Key:       rsaKey,
	}
	if kid != "" {
		recipient.KeyID = kid
	}

	opts := (&jose.EncrypterOptions{}).WithContentType("JWT")
	if kid != "" {
		opts.WithHeader("kid", kid)
	}

	encrypter, err := jose.NewEncrypter(jose.A256GCM, recipient, opts)
	if err != nil {
		return "", fmt.Errorf("new encrypter: %w", err)
	}

	jwe, err := encrypter.Encrypt([]byte(signedJWT))
	if err != nil {
		return "", fmt.Errorf("encrypt jwt: %w", err)
	}
	return jwe.CompactSerialize()
}

func (s *Service) Decrypt(assertion string) (string, error) {
	if s.encryptionPrivate == nil {
		return "", ErrNoDecryptionKey
	}
	jwe, err := jose.ParseEncrypted(assertion)
	if err != nil {
		return "", fmt.Errorf("parse encrypted: %w", err)
	}
	payload, err := jwe.Decrypt(s.encryptionPrivate)
	if err != nil {
		return "", fmt.Errorf("decrypt assertion: %w", err)
	}
	return string(payload), nil
}

func (s *Service) HasDecryptionKey() bool {
	return s.encryptionPrivate != nil
}

func (s *Service) SigningPublicJWK() jose.JSONWebKey {
	return jose.JSONWebKey{
		Key:       s.signingPublicKey,
		KeyID:     s.signingKID,
		Algorithm: string(s.signingAlg),
		Use:       "sig",
	}
}

func (s *Service) EncryptionPublicJWK() *jose.JSONWebKey {
	if s.encryptionPublic == nil {
		return nil
	}
	jwk := jose.JSONWebKey{
		Key:       s.encryptionPublic,
		Algorithm: string(jose.RSA_OAEP_256),
		Use:       "enc",
	}
	if s.signingKID != "" {
		jwk.KeyID = s.signingKID + "-enc"
	}
	return &jwk
}

func loadPrivateKey(path string) (interface{}, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("key file %s not found", path)
		}
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block in %s", path)
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		switch k := key.(type) {
		case *rsa.PrivateKey:
			return k, nil
		case *ecdsa.PrivateKey:
			return k, nil
		default:
			return nil, fmt.Errorf("unsupported pkcs8 key type %T", k)
		}
	}
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrUnsupportedKey, path)
}

func signatureAlgorithmForKey(key interface{}) (jose.SignatureAlgorithm, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return jose.RS256, nil
	case *ecdsa.PrivateKey:
		switch k.Curve {
		case elliptic.P256():
			return jose.ES256, nil
		case elliptic.P384():
			return jose.ES384, nil
		case elliptic.P521():
			return jose.ES512, nil
		default:
			return "", fmt.Errorf("unsupported ecdsa curve: %s", k.Curve.Params().Name)
		}
	default:
		return "", ErrUnsupportedKey
	}
}

func publicFromPrivate(key interface{}) (interface{}, error) {
	switch k := key.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey, nil
	case *ecdsa.PrivateKey:
		return &k.PublicKey, nil
	default:
		return nil, ErrUnsupportedKey
	}
}

func ParsePublicKeyPEM(pemData string) (interface{}, error) {
	block, _ := pem.Decode([]byte(pemData))
	if block == nil {
		return nil, fmt.Errorf("invalid PEM data")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err == nil {
		switch pub.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
			return pub, nil
		default:
			return nil, fmt.Errorf("unsupported public key type %T", pub)
		}
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err == nil {
		return cert.PublicKey, nil
	}
	return nil, fmt.Errorf("parse public key: %w", err)
}

func nilStringErr(msg string) (string, error) {
	return "", errors.New(msg)
}

func MustPEM(data []byte) string {
	trimmed := strings.TrimSpace(string(data))
	return trimmed
}
