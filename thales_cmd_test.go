package thales9000

import (
	"testing"
	"net"
	"time"
	"crypto/rsa"
	"encoding/asn1"
	"crypto"
	"crypto/sha256"
	"crypto/sha512"
	"hash"
	"crypto/sha1"
	"fmt"
	"strings"
	"crypto/rand"
	"bytes"
)
const (
	TEST_THALES_HSM_HOST     string = "10.101.70.194:1500"
	HSM_CONNECTION_TIMEOUT   int64  = 2
)
// =============================================================================
//  Helper test function to verify signature by private Thales key
//  and by output public key by different key length
// =============================================================================
func verifySignatureRsaBitsTest(t *testing.T, conn net.Conn, rsaBits int) {
	mac,pubBytes,privBytes, err := thalesGenerateRSAKeyPair(conn, rsaBits)
	if err != nil {
		t.Fatalf("[THALES]: Failed to generate RSA private/public (%d) key pairs: %s\n", rsaBits,err)
	}

	// Verify signature by that generated data SHA1, SHA256, SHA224, SHA384, SHA512 and no hash
	verifySignatureTest(t, conn, mac, pubBytes, privBytes, crypto.SHA1)
	verifySignatureTest(t, conn, mac, pubBytes, privBytes, crypto.SHA224)
	verifySignatureTest(t, conn, mac, pubBytes, privBytes, crypto.SHA256)
	verifySignatureTest(t, conn, mac, pubBytes, privBytes, crypto.SHA384)
	verifySignatureTest(t, conn, mac, pubBytes, privBytes, crypto.SHA512)
	verifySignatureTest(t, conn, mac, pubBytes, privBytes, THALES_NO_HASH_SIGN)
}
// =============================================================================
//  Helper test function to verify signature by private Thales key
//  and by output public key
// =============================================================================
func verifySignatureTest(t *testing.T, conn net.Conn, mac []byte, pubBytes []byte, privBytes []byte, hashType crypto.Hash) {
	var pubKey rsa.PublicKey
	var h hash.Hash  // Hash function

	// Test sign data
	msg := []byte("Dummy sign message")

	switch hashType {
	case crypto.SHA1:
		h = sha1.New()
	case crypto.SHA224:
		h = sha256.New224()
	case crypto.SHA256:
		h = sha256.New()
	case crypto.SHA384:
		h = sha512.New384()
	case crypto.SHA512:
		h = sha512.New()
	case THALES_NO_HASH_SIGN:
		h = sha256.New()
	default:
		t.Fatal("[THALES]: Unknown hash function\n")
	}
	// Calculate hash for verification
	h.Write([]byte(msg))
	hashed := h.Sum(nil)

	if hashType == THALES_NO_HASH_SIGN {
		prefix, ok := hashPrefixes[crypto.SHA256]; if !ok {
			t.Fatal("[THALES]: Unknown hash function\n")
		}
		msg = append(prefix, hashed...)
	}

	// Create output public key
	if rest, err := asn1.Unmarshal(pubBytes, &pubKey); err != nil {
		t.Fatalf("[THALES]: Failed create output RSA public key from ASN.1 data: %s\n", err)
	} else if len(rest) != 0 {
		t.Fatalf("[THALES]: Failed create output RSA public key from ASN.1 data, additional bytes is present\n")
	}

	// Generate signature by HSM
	sign, err := thalesGenerateRSASignature(conn, msg, privBytes, hashType)
	if err != nil {
		t.Fatalf("[THALES]: Failed to generate RSA signature [SHA512]: %s\n", err)
	}

	// Validate signature by HSM
	if err := thalesValidateSignatureRSA(conn, msg, sign, mac, pubBytes, hashType); err != nil {
		t.Fatalf("[THALES]: Failed to validate signature [SHA512] by HSM RSA public key: %s\n", err)
	}

	// Redefine hash type
	if hashType == THALES_NO_HASH_SIGN {
		hashType = crypto.SHA256
	}

	// Validate by output public key
	if err:= rsa.VerifyPKCS1v15(&pubKey, hashType, hashed, sign[4:]); err != nil {
		t.Fatalf("[THALES]: Failed to verify RSA signature by output private key: %s\n", err)
	}
}
// =============================================================================
//  Test generate RSA key pair (public/private keys) and also
//  verify signature by that pair with two cases:
//      by internal Thales verification command
//      by external public key generation
// =============================================================================
func TestGenerateRSAkeyPair(t *testing.T) {
	conn, err := net.DialTimeout("tcp", TEST_THALES_HSM_HOST, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		t.Fatalf("[THALES]: Failed to HSM connect: %s\n", err)
	}
	defer conn.Close()

	//verifySignatureRsaBitsTest(t, conn,512)
	verifySignatureRsaBitsTest(t, conn,1024)
	verifySignatureRsaBitsTest(t, conn,2048)
	//verifySignatureRsaBitsTest(t, conn,4096)
}
// =============================================================================
//  Thales test generate RSA key private.public pair and verify signature
//  by public key
// =============================================================================
func TestGenerateThalesRSAkeyPair(t *testing.T) {
	conn, err := net.DialTimeout("tcp", TEST_THALES_HSM_HOST, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		t.Fatalf("[THALES]: Failed to HSM connect: %s\n", err)
	}
	defer conn.Close()

	key, err := CreateRSAKey(conn, 1024)
	if err != nil {
		t.Fatalf("[THALES]: Failed creating rsa key pair: %s\n", err)
	}

	// Test sign data
	hashed := sha256.Sum256([]byte("Dummy sign message"))

	sign, err := key.Sign(nil, hashed[:], crypto.SHA256)
	if err != nil {
		t.Fatalf("[THALES]: Failed to generate RSA signature: %s\n", err)
	}

	if err := rsa.VerifyPKCS1v15(key.PublicKey, crypto.SHA256, hashed[:], sign); err != nil {
		t.Fatalf("[THALES]: Failed to verify RSA signature by output private key: %s\n", err)
	}
}

func xTestEncryptDecryptThales(t *testing.T) {
	conn, err := net.DialTimeout("tcp", TEST_THALES_HSM_HOST, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		t.Fatalf("[THALES]: Failed to HSM connect: %s\n", err)
	}
	defer conn.Close()

	key := "U35008F52E8B5F4CF0DB0FBF4E516EDDB"
	msg := []byte("MMM-VVV0")

	data, err := thalesEncryptDataBlock(conn, msg, key)
	if err != nil {
		t.Fatalf("[THALES]: Couldn't ecrypt data block: %s\n", err)
	}

	out_msg, err := thalesDecryptDataBlock(conn, data, key)
	if err != nil {
		t.Fatalf("[THALES]: Couldn't decrypt data block: %s\n", err)
	}

	fmt.Println(out_msg)
}
// =============================================================================
//  Thales test generate symmetric key commands
// =============================================================================
func xTestThalesGenerateSymmetricKey(t *testing.T) {
	conn, err := net.DialTimeout("tcp", TEST_THALES_HSM_HOST, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		t.Fatalf("[THALES]: Failed to HSM connect: %s\n", err)
	}
	defer conn.Close()

	_,err = thalesGenerateSymmetricKey(conn)

	if err != nil {
		t.Fatalf("[THALES]: Couldn't generate symmetric key: %s\n", err)
	}
}
// =============================================================================
//  Thales test generate & verify MAC commands
// =============================================================================
func TestThalesGenerateMAC(t *testing.T) {
	conn, err := net.DialTimeout("tcp", TEST_THALES_HSM_HOST, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		t.Fatalf("[THALES]: Failed to HSM connect: %s\n", err)
	}
	defer conn.Close()

	mac := "0ECFBDB183EF325F"
	clearKey := "0123456789ABCDEFABCDEF0123456789"
	key := "U7B7B1BE6AFBA184A2A6201710459AC7B"     // ZAK key in HSM
	msg := []byte("MMM-VVV0")

	b,err := thalesGenerateMAC(conn, msg, key)

	if err != nil {
		t.Fatalf("[THALES]: Couldn't generate MAC: %s\n", err)
	}

	if !strings.EqualFold(string(b), mac) {
		t.Fatalf("[THALES]: Invalid mac [clear key: %s]: %s\n\texpected: %s\n", clearKey, string(b), mac)
	}

	_, err = thalesVerifyMAC(conn, msg, string(mac), key)
	if err != nil {
		t.Fatalf("[THALES]: Couldn't verify MAC: %s\n", err)
	}
}
// =============================================================================
//  Thales test generate RSA signature for binary buffer
// =============================================================================
func xTestThalesGenerateRSASignature(t *testing.T) {

	conn, err := net.DialTimeout("tcp", TEST_THALES_HSM_HOST, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		t.Fatalf("[THALES]: Failed to HSM connect: %s\n", err)
	}
	defer conn.Close()

	var msg = []byte {
		0x59, 0x95, 0xBE, 0xE4, 0xDD, 0xBE, 0x0E, 0x84,
		0x86, 0x56, 0xBE, 0x43, 0xD9, 0x19, 0xC0, 0x13,
		0xBA, 0x9B, 0x6A, 0x54, 0x87, 0xCC, 0x1F, 0xB2,
		0x19, 0x56, 0x13, 0x67, 0xAE, 0xD9, 0x1A, 0x9F,
		0xE1, 0xA7, 0x20, 0xA5 }

	_,_,privBytes, err := thalesGenerateRSAKeyPair(conn, 2048)
	if err != nil {
		t.Fatalf("[THALES]: Failed to generate RSA private/public (%d) key pairs: %s\n", 2048,err)
	}

	// Generate signature by HSM
	_, err = thalesGenerateRSASignature(conn, msg, privBytes, THALES_NO_HASH_SIGN)
	if err != nil {
		t.Fatalf("[THALES]: Failed to generate RSA signature [No hash]: %s\n", err)
	}
}
// =============================================================================
//  Thales test decrypt by RSA private key
// =============================================================================
func TestThalesDecryptDataRSAPrivateKey(t *testing.T) {
	conn, err := net.DialTimeout("tcp", TEST_THALES_HSM_HOST, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		t.Fatalf("[THALES]: Failed to HSM connect: %s\n", err)
	}
	defer conn.Close()

	key, err := CreateRSAKey(conn, 2048)
	if err != nil {
		t.Fatalf("[THALES]: Failed creating rsa key pair: %s\n", err)
	}

	// Test sign data
	msg := []byte("Dummy encrypt message")

	// Encrypt the data
	enc, err := rsa.EncryptPKCS1v15(rand.Reader, key.Public().(*rsa.PublicKey), msg)
	if err != nil {
		t.Fatalf("[THALES]: Failed encrypt data by public key: %s\n", err)
	}

	dec,err := thalesDecryptDataBlockRSA(conn, enc, key.pkeyBytes)
	if err != nil {
		t.Fatalf("[THALES]: Failed decrypt data by private key: %s\n", err)
	}

	if !bytes.Equal(msg, dec[4:]) {
		t.Fatalf("[THALES]: Invalid decrypt message: %s\n\texpected: %s\n", string(msg), string(dec[4:]))
	}
}