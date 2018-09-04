package thales9000

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
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

// BlockType is a PEM block type.
type BlockType string

// String satisfies the string interface for a block type.
func (bt BlockType) String() string {
	return string(bt)
}

const (
	// PrivateKey is the "PRIVATE KEY" block type.
	PrivateKeyBlock BlockType = "PRIVATE KEY"

	// RSAPrivateKey is the "RSA PRIVATE KEY" block type.
	RSAPrivateKeyBlock BlockType = "RSA PRIVATE KEY"

	// ECPrivateKey is the "EC PRIVATE KEY" block type.
	ECPrivateKeyBlock BlockType = "EC PRIVATE KEY"

	// PublicKey is the "PUBLIC KEY" block type.
	PublicKeyBlock BlockType = "PUBLIC KEY"

	// Certificate is the "CERTIFICATE" block type.
	CertificateBlock BlockType = "CERTIFICATE"
)

// =============================================================================
//   CreateRSAKey creates a new Thales key using RSA algorithm
// =============================================================================
func CreateThalesRSAKey(conn net.Conn, rsaBits int, keyType int) (*RsaThalesPrivKey, error) {

	/* Generate private - public key pair, skip mac response  */
	_, pubBytes, privBytes, err := thalesGenerateRSAKeyPair(conn, rsaBits, keyType)
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
type RsaThalesPrivKey struct {
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
func NewThalesPrivKey(cryptoPublicKey *rsa.PublicKey, privBytes []byte, c net.Conn) *RsaThalesPrivKey {
	return &RsaThalesPrivKey{cryptoPublicKey, privBytes, c}
}
// =============================================================================
//  New instantiates a new Thales private key from files
// =============================================================================
func NewThalesPrivKeyFromFiles(publicKeyPath, privateKeyPath string, c net.Conn) (*RsaThalesPrivKey,error) {
	var err error
	var block *pem.Block

	buf, err := ioutil.ReadFile(publicKeyPath)
	if err != nil {
		return nil,err
	}

	// loop over pem encoded data
	if len(buf) > 0 {
		block, buf = pem.Decode(buf)
		if block == nil {
			return nil, errors.New("thales9000: invalid PEM data")
		}

		if BlockType(block.Type) != PublicKeyBlock {
			return nil, errors.New("thales9000: invalid PEM block type")
		}

		pk, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			// use the raw b64 decoded bytes
			pk = block.Bytes
		}

		rsaPubKey, ok := pk.(*rsa.PublicKey)
		if ok {
			buf, err := ioutil.ReadFile(privateKeyPath)
			if err != nil {
				return nil,err
			}

			return NewThalesPrivKey( rsaPubKey, buf, c),nil
		}
	}

	return nil, errors.New("thales: Couldn't create Thales private key from files")
}
// =============================================================================
//  Public returns the public key for Thales private key
// =============================================================================
func (pk *RsaThalesPrivKey) Public() crypto.PublicKey {
	return pk.PublicKey
}
// =============================================================================
//  Sign performs a signature using the Thales private key
// =============================================================================
func (pk *RsaThalesPrivKey) Sign(rand io.Reader, msg []byte, opts crypto.SignerOpts) (signature []byte, err error) {

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

		prefix, ok := hashPrefixes[hash]
		if !ok {
			err = errors.New("thales9000: unknown hash prefix")
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

// ================================================================================
//  Writes the private key data to filename with mode 0600
// ================================================================================
func (pk RsaThalesPrivKey) WritePrivateKeyToFile(filename string) error {
	if len(pk.pkeyBytes) == 0 {
		return errors.New("thales9000: Invalid private key data")
	}
	return ioutil.WriteFile(filename, pk.pkeyBytes, 0600)
}
// ================================================================================
//  Writes the public key data to filename with mode 0600
// ================================================================================
func (pk RsaThalesPrivKey) WritePublicKeyToFile(filename string) error {
	var err error
	var typ BlockType
	var buf []byte

	switch v := pk.Public().(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey:
		typ = PublicKeyBlock
		if buf, err = x509.MarshalPKIXPublicKey(v); err != nil {
			return err
		}

	default:
		return errors.New("thales9000: unsupported crypto primitive")
	}

	b := pem.EncodeToMemory(&pem.Block{
		Type:  typ.String(),
		Bytes: buf,
	})

	return ioutil.WriteFile(filename, b, 0600)
}
// ================================================================================
//  Writes the public key data to filename with mode 0600
// ================================================================================
func (pk RsaThalesPrivKey) PrivateKeyBytes() []byte {
	return pk.pkeyBytes
}