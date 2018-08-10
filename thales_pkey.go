package thales9000

import (
	"crypto"
	"io"
	"fmt"
	"crypto/rsa"
	"net"
	"encoding/asn1"
	"errors"
)
var hashPrefixes = map[crypto.Hash][]byte{
	crypto.MD5:       {0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04, 0x10},
	crypto.SHA1:      {0x30, 0x21, 0x30, 0x09, 0x06, 0x05, 0x2b, 0x0e, 0x03, 0x02, 0x1a, 0x05, 0x00, 0x04, 0x14},
	crypto.SHA224:    {0x30, 0x2d, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x04, 0x05, 0x00, 0x04, 0x1c},
	crypto.SHA256:    {0x30, 0x31, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01, 0x05, 0x00, 0x04, 0x20},
	crypto.SHA384:    {0x30, 0x41, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02, 0x05, 0x00, 0x04, 0x30},
	crypto.SHA512:    {0x30, 0x51, 0x30, 0x0d, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03, 0x05, 0x00, 0x04, 0x40},
	crypto.MD5SHA1:   {}, // A special TLS case which doesn't use an ASN1 prefix.
	crypto.RIPEMD160: {0x30, 0x20, 0x30, 0x08, 0x06, 0x06, 0x28, 0xcf, 0x06, 0x03, 0x00, 0x31, 0x04, 0x14},
}

// =============================================================================
//   CreateRSAKey creates a new Thales key using RSA algorithm
// =============================================================================
func CreateRSAKey(conn net.Conn, rsaBits int) (*rsaThalesPrivKey, error) {

	/* Generate private - public key pair, skip mac response  */
	_, pubBytes, privBytes, err := thalesGenerateRSAKeyPair(conn, rsaBits)
	if err != nil {
		return nil, err
	}

	var pubKey rsa.PublicKey

	if rest, err := asn1.Unmarshal(pubBytes, &pubKey); err != nil {
		return nil, err
	} else if len(rest) != 0 {
		return nil, errors.New("thales9000: Failed create output RSA public key from ASN.1 data, additional bytes is present")
	}
	// Create Thales private key instance
	return NewThalesPrivKey(&pubKey, privBytes, conn), nil
}
// =============================================================================
//  Key contains a public-private Thales keypair
// =============================================================================
type rsaThalesPrivKey struct {
	*rsa.PublicKey
	// byte buffer 'Private Key' is encrypted under LMK pair 34-35
	// first 4 bytes length (in bytes) format: 4N
	pkeyBytes []byte
	// Thales HSM socket connection
	conn net.Conn
}
// =============================================================================
//  New instantiates a new Thales private key
// =============================================================================
func NewThalesPrivKey(cryptoPublicKey *rsa.PublicKey, privBytes []byte, c net.Conn) (*rsaThalesPrivKey) {

	return &rsaThalesPrivKey{cryptoPublicKey, privBytes, c}
}
// =============================================================================
//  Public returns the public key for Thales private key
// =============================================================================
func (pk *rsaThalesPrivKey) Public() crypto.PublicKey {
	return pk.PublicKey
}
// =============================================================================
//  Sign performs a signature using the Thales private key
// =============================================================================
func (pk *rsaThalesPrivKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {

	// Verify that the length of the hash is as expected
	hash := opts.HashFunc()
	hashLen := hash.Size()
	if len(msg) != hashLen {
		err = fmt.Errorf("thales9000: input size does not match hash function output size: %d vs %d", len(msg), hashLen)
		return
	}

	// Add DigestInfo prefix
	var signIn []byte

	switch pk.Public().(type) {
	case *rsa.PublicKey:
		if _, ok := hashThalesType[hash];  !ok {
			err = fmt.Errorf("thales9000: unknown hash function")
			return
		}

		prefix, ok := hashPrefixes[hash]; if !ok {
			err = errors.New("pkcs11key: unknown hash function")
			return
		}
		signIn = append(prefix, msg...)
	default:
		return nil, fmt.Errorf("thales9000: unrecognized key type %T", pk.PublicKey)
	}

	signature, err = thalesGenerateRSASignature(pk.conn, signIn, pk.pkeyBytes, THALES_NO_HASH_SIGN)
	if err != nil {
		return nil, err
	}

	/* Skip first 4 bytes as signature length */
	return signature[4:], nil
}