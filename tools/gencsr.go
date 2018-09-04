package main

import (
	"fmt"
	"net"
	"strings"
	"net/mail"
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"../../go-thales9000"
	"crypto/rsa"
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/hex"
	"os"
)

// =============================================================================
// A Name contains the SubjectInfo fields
// =============================================================================
type Name struct {
	C            string // Country
	ST           string // State
	L            string // Locality
	O            string // OrganisationName
	OU           string // OrganisationalUnitName
	SerialNumber string
}
// =============================================================================
// KeyRequest is a generic request for a new key
// =============================================================================
type KeyRequest interface {
	Algo() string
	Size() int
	Type() int
	Generate(conn net.Conn) (crypto.PrivateKey, error)
	SigAlgo() x509.SignatureAlgorithm
	Save(key *thales9000.RsaThalesPrivKey)
}
// =============================================================================
// BasicKeyRequest contains the algorithm, key size and type for a new private key
// =============================================================================
type BasicKeyRequest struct {
	A string `json:"algo" yaml:"algo"`
	S int    `json:"size" yaml:"size"`
	T int    `json:"type" yaml:"type"`

	PrivFilePath string  `json:"privFilePath,omitempty" yaml:"privFilePath,omitempty"`
	PubFilePath  string  `json:"pubFilePath,omitempty" yaml:"pubFilePath,omitempty"`
}
// =============================================================================
// A CertificateRequest encapsulates the API interface to the
// certificate request functionality
// =============================================================================
type CertificateRequest struct {
	CN           string
	HsmAddress	 string     `json:"hsm" yaml:"hsm"`
	Names        []Name     `json:"names" yaml:"names"`
	Hosts        []string   `json:"hosts" yaml:"hosts"`
	KeyRequest   KeyRequest `json:"key,omitempty" yaml:"key,omitempty"`
	SerialNumber string     `json:"serialnumber,omitempty" yaml:"serialnumber,omitempty"`
	CsrFilePath  string     `json:"csrFilePath,omitempty" yaml:"csrFilePath,omitempty"`
}
// =============================================================================
// NewBasicKeyRequest returns a default BasicKeyRequest
// =============================================================================
func NewBasicKeyRequest() *BasicKeyRequest {
	return &BasicKeyRequest{"rsa", 2048, 4, "", ""}
}
// =============================================================================
// Algo returns the requested key algorithm represented as a string
// =============================================================================
func (kr *BasicKeyRequest) Algo() string {
	return kr.A
}
// =============================================================================
// Size returns the requested key size
// =============================================================================
func (kr *BasicKeyRequest) Size() int {
	return kr.S
}
// =============================================================================
// Type returns the requested key type (sign or ssl support)
// =============================================================================
func (kr *BasicKeyRequest) Type() int {
	return kr.T
}
// =============================================================================
// Generate generates a key as specified in the request. Currently,
// only RSA are supported
// =============================================================================
func (kr *BasicKeyRequest) Generate(conn net.Conn) (crypto.PrivateKey, error) {

	switch kr.Algo() {
	case "rsa":
		if kr.Size() < 2048 {
			return nil, errors.New("RSA key is too weak")
		}
		if kr.Size() > 8192 {
			return nil, errors.New("RSA key size too large")
		}
		if kr.Type() != 0 && kr.Type() != 4 {
			return nil, errors.New("RSA key type is not supported")
		}
		// Create Thales private RSA key
		return thales9000.CreateThalesRSAKey(conn,kr.Size(),kr.Type())
	default:
		return nil, errors.New("invalid algorithm")
	}
}
// =============================================================================
// SigAlgo returns an appropriate X.509 signature algorithm given the
// key request's type and size
// =============================================================================
func (kr *BasicKeyRequest) SigAlgo() x509.SignatureAlgorithm {
	switch kr.Algo() {
	case "rsa":
		switch {
		case kr.Size() >= 4096:
			return x509.SHA512WithRSA
		case kr.Size() >= 3072:
			return x509.SHA384WithRSA
		case kr.Size() >= 2048:
			return x509.SHA256WithRSA
		default:
			return x509.SHA1WithRSA
		}
	default:
		return x509.UnknownSignatureAlgorithm
	}
}
// =============================================================================
// Save save private & public keys
// =============================================================================
func (kr *BasicKeyRequest) Save(key *thales9000.RsaThalesPrivKey) {
	empty := func(s string) bool { return strings.TrimSpace(s) == "" }
	// Write private key to file
	if !empty( kr.PrivFilePath ) {
		key.WritePrivateKeyToFile(kr.PrivFilePath)
	} else {
		fmt.Fprintf(os.Stdout,"\nPrivate key data:\n");
		fmt.Println(hex.Dump(key.PrivateKeyBytes()))
	}

	// Write public key to file
	if !empty( kr.PubFilePath ) {
		key.WritePublicKeyToFile(kr.PubFilePath)
	} else {
		fmt.Fprintf(os.Stdout,"\nPublic key:\n");
	}
}
// =============================================================================
// appendIf appends to a if s is not an empty string
// =============================================================================
func appendIf(s string, a *[]string) {
	if s != "" {
		*a = append(*a, s)
	}
}
// =============================================================================
// Name returns the PKIX name for the request
// =============================================================================
func (cr *CertificateRequest) Name() pkix.Name {
	var name pkix.Name
	name.CommonName = cr.CN

	for _, n := range cr.Names {
		appendIf(n.C, &name.Country)
		appendIf(n.ST, &name.Province)
		appendIf(n.L, &name.Locality)
		appendIf(n.O, &name.Organization)
		appendIf(n.OU, &name.OrganizationalUnit)
	}
	name.SerialNumber = cr.SerialNumber
	return name
}
// =============================================================================
// Generate creates a new CSR from a CertificateRequest structure and
// an existing key. The KeyRequest field is ignored
// =============================================================================
func GenerateCSR(priv crypto.Signer, req *CertificateRequest) (csr []byte, err error) {
	sigAlgo := signerAlgo(priv)
	if sigAlgo == x509.UnknownSignatureAlgorithm {
		return nil, errors.New("Private key is unavailable")
	}

	var tpl = x509.CertificateRequest{
		Subject:            req.Name(),
		SignatureAlgorithm: sigAlgo,
	}

	for i := range req.Hosts {
		if ip := net.ParseIP(req.Hosts[i]); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else if email, err := mail.ParseAddress(req.Hosts[i]); err == nil && email != nil {
			tpl.EmailAddresses = append(tpl.EmailAddresses, email.Address)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, req.Hosts[i])
		}
	}

/*
	if req.CA != nil {
		err = appendCAInfoToCSR(req.CA, &tpl)
		if err != nil {
			err = cferr.Wrap(cferr.CSRError, cferr.GenerationFailed, err)
			return
		}
	}
*/
	csr, err = x509.CreateCertificateRequest(rand.Reader, &tpl, priv)
	if err != nil {
		return nil, fmt.Errorf("Failed to generate a CSR: %v", err)
	}
	block := pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	}

	csr = pem.EncodeToMemory(&block)
	return
}
// =============================================================================
// IsNameEmpty returns true if the name has no identifying information in it
// =============================================================================
func IsNameEmpty(n Name) bool {
	empty := func(s string) bool { return strings.TrimSpace(s) == "" }

	if empty(n.C) && empty(n.ST) && empty(n.L) && empty(n.O) && empty(n.OU) {
		return true
	}
	return false
}
// =============================================================================
// SignerAlgo returns an X.509 signature algorithm from a crypto.Signer
// =============================================================================
func signerAlgo(priv crypto.Signer) x509.SignatureAlgorithm {
	switch pub := priv.Public().(type) {
	case *rsa.PublicKey:
		bitLength := pub.N.BitLen()
		switch {
		case bitLength >= 4096:
			return x509.SHA512WithRSA
		case bitLength >= 3072:
			return x509.SHA384WithRSA
		case bitLength >= 2048:
			return x509.SHA256WithRSA
		default:
			return x509.SHA1WithRSA
		}
	case *ecdsa.PublicKey:
		switch pub.Curve {
		case elliptic.P521():
			return x509.ECDSAWithSHA512
		case elliptic.P384():
			return x509.ECDSAWithSHA384
		case elliptic.P256():
			return x509.ECDSAWithSHA256
		default:
			return x509.ECDSAWithSHA1
		}
	default:
		return x509.UnknownSignatureAlgorithm
	}
}