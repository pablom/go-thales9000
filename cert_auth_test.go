// cert_auth_test.go

package thales9000

import (
	"testing"
	"time"
)

const (
	ROOT_CA_PATH     string = "sslCA"
	ROOT_CA_CERT_NAME  string  = "owroot_thales.crt"
	ROOT_CA_KEY_NAME   string  = "owroot_thales.key"
)

func TestCreateCertificateAuthority(t *testing.T) {
	key, err := CreateRSAKey(2048)
	if err != nil {
		t.Fatal("Failed creating rsa key:", err)
	}

	crt, err := CreateCertificateAuthority(key, "OU", time.Now().AddDate(5, 0, 0), "test", "US", "California", "San Francisco", "CA Name")
	if err != nil {
		t.Fatal("Failed creating certificate authority:", err)
	}
	rawCrt, err := crt.GetRawCertificate()
	if err != nil {
		t.Fatal("Failed to get x509.Certificate:", err)
	}

	if err = rawCrt.CheckSignatureFrom(rawCrt); err != nil {
		t.Fatal("Failed to check signature:", err)
	}

	if rawCrt.Subject.OrganizationalUnit[0] != "OU" {
		t.Fatal("Failed to verify hostname:", err)
	}

	if !time.Now().After(rawCrt.NotBefore) {
		t.Fatal("Failed to be after NotBefore")
	}

	if !time.Now().Before(rawCrt.NotAfter) {
		t.Fatal("Failed to be before NotAfter")
	}
}

func TestCreateRootCertificateAuthority(t *testing.T) {

	if err := CreateNewRootCA(ROOT_CA_PATH, ROOT_CA_CERT_NAME, ROOT_CA_KEY_NAME); err != nil {
		t.Fatal("Failed to create root CA Thales test certificate authority")
	}

}
