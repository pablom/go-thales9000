package thales9000

import (
	"testing"
	"net"
	"time"
	"io/ioutil"
	"crypto/rsa"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"crypto/x509/pkix"
	"crypto/ecdsa"
	"bytes"
	"encoding/pem"
	"fmt"
	"os"
)

const (
	CA_KEY_PATH         string = "ca.key"
	CA_CERT_PATH        string  = "ca.crt"
	TEST_CERT_REQ_PATH  string  = "test.csr"
	TEST_CERT_PATH      string  = "test.crt"

	csrHostname = "host1"
	csrCN       = "CN"
)



func publicKey(priv interface{}) interface{} {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &k.PublicKey
	case *ecdsa.PrivateKey:
		return &k.PublicKey
	default:
		return nil
	}
}

func pemBlockForKey(priv interface{}) *pem.Block {
	switch k := priv.(type) {
	case *rsa.PrivateKey:
		return &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}
	case *ecdsa.PrivateKey:
		b, err := x509.MarshalECPrivateKey(k)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Unable to marshal ECDSA private key: %v", err)
			os.Exit(2)
		}
		return &pem.Block{Type: "EC PRIVATE KEY", Bytes: b}
	default:
		return nil
	}
}

func TestCreateCertificateSigningRequest(t *testing.T) {

	conn, err := net.DialTimeout("tcp", TEST_THALES_HSM_HOST, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		t.Fatalf("[THALES]: Failed to HSM connect: %s\n", err)
	}

	defer conn.Close()

	key, err := CreateRSAKey(conn, 1024)
	if err != nil {
		t.Fatal("[THALES]: Failed creating rsa key pair:", err)
	}

	csr, err := CreateCertificateSigningRequest(key, csrHostname, nil, nil,
		"example", "US", "California", "San Francisco", csrCN)

	if err != nil {
		t.Fatal("Failed creating certificate request:", err)
	}

	if err = csr.CheckSignature(); err != nil {
		t.Fatal("Failed checking signature in certificate request:", err)
	}

	rawCsr, err := csr.GetRawCertificateSigningRequest()
	if err != nil {
		t.Fatal("Failed getting raw certificate request:", err)
	}

	if csrHostname != rawCsr.Subject.OrganizationalUnit[0] {
		t.Fatalf("Expect OrganizationalUnit to be %v instead of %v", csrHostname, rawCsr.Subject.OrganizationalUnit[0])
	}
	if csrCN != rawCsr.Subject.CommonName {
		t.Fatalf("Expect CommonName to be %v instead of %v", csrCN, rawCsr.Subject.CommonName)
	}

	// Export certificate request to file
	b, err := csr.Export()
	if err != nil {
		t.Fatal("Failed to export certificate request as pem bytes: ", err)
	}

	err = ioutil.WriteFile(TEST_CERT_REQ_PATH, b, 0644)
	if err != nil {
		t.Fatal("Failed export to file certificate request: ", err)
	}

	// Generate private key for self sign certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal("Failed generate RSA private key for self sign certificate:", err)
	}
	// Generate self sign certificate to sign certificate request
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Fake News"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(time.Hour * 24 * 180),

		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, publicKey(priv), priv)
	if err != nil {
		t.Fatal("Failed to create certificate: ", err)
	}

	out := &bytes.Buffer{}
	pem.Encode(out, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	//fmt.Println(out.String())
	err = ioutil.WriteFile(CA_CERT_PATH, out.Bytes(), 0644)
	if err != nil {
		t.Fatal("Failed export to file self-sign certificate: ", err)
	}
	out.Reset()
	pem.Encode(out, pemBlockForKey(priv))
	//fmt.Println(out.String())
	err = ioutil.WriteFile(CA_KEY_PATH, out.Bytes(), 0644)
	if err != nil {
		t.Fatal("Failed export to file self-sign certificate: ", err)
	}

	err = CsrToCrt(CA_CERT_PATH, CA_KEY_PATH, TEST_CERT_REQ_PATH, TEST_CERT_PATH, "")
	if err != nil {
		t.Fatal("Failed to get crt:", err)
	}

	// Delete temporary files
	os.Remove(CA_CERT_PATH)
	os.Remove(CA_KEY_PATH)
	os.Remove(TEST_CERT_PATH)
	os.Remove(TEST_CERT_REQ_PATH)
}
