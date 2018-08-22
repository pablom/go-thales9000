package thales9000

import (
	"testing"
	"net"
	"time"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"os"
)

const (
	PRIVATE_KEY_PATH  string = "thales_pkey.data"
	PUBLIC_KEY_PATH   string  = "thales_public_key.pem"
)

// =============================================================================
//  Thales test generate RSA private & save data to files
// =============================================================================
func TestCreateRSAPrivateKey(t *testing.T) {
	conn, err := net.DialTimeout("tcp", TEST_THALES_HSM_HOST, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		t.Fatalf("[THALES]: Failed to HSM connect: %s\n", err)
	}

	defer conn.Close()

	key, err := CreateRSAKey(conn, 1024)
	if err != nil {
		t.Fatal("[THALES]: Failed creating rsa key pair:", err)
	}

	if err = key.WritePrivateKeyToFile(PRIVATE_KEY_PATH); err != nil {
		t.Fatal("[THALES]: Failed create thales rsa private key file:", err)
	}

	if err = key.WritePublicKeyToFile(PUBLIC_KEY_PATH); err != nil {
		t.Fatal("[THALES]: Failed create thales rsa public key file:", err)
	}
}
// =============================================================================
//  Thales test load RSA private/public keys from files and verify signature
// =============================================================================
func TestCreateRSAPrivateKeyFromFile(t *testing.T) {
	conn, err := net.DialTimeout("tcp", TEST_THALES_HSM_HOST, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		t.Fatalf("[THALES]: Failed to HSM connect: %s\n", err)
	}

	defer conn.Close()

	pk, err := NewThalesPrivKeyFromFiles(PUBLIC_KEY_PATH, PRIVATE_KEY_PATH, conn)
	if err != nil {
		t.Fatal("[THALES]: Failed creating rsa key from file:", err)
	}

	// Test sign data
	msg := []byte("Dummy sign message")

	// Generate signature by HSM
	sign, err := thalesGenerateRSASignature(conn, msg, pk.pkeyBytes, crypto.SHA256)
	if err != nil {
		t.Fatalf("[THALES]: Failed to generate RSA signature [SHA512]: %s\n", err)
	}

	h := sha256.New()
	// Calculate hash for verification
	h.Write([]byte(msg))
	hashed := h.Sum(nil)

	// Validate by output public key
	if err:= rsa.VerifyPKCS1v15(pk.Public().(*rsa.PublicKey), crypto.SHA256, hashed, sign[4:]); err != nil {
		t.Fatalf("[THALES]: Failed to verify RSA signature by output private key: %s\n", err)
	}

	// Delete temporary files
	os.Remove(PUBLIC_KEY_PATH)
	os.Remove(PRIVATE_KEY_PATH)
}

