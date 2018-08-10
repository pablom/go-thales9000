package thales9000

import (
	"testing"
	"net"
	"time"
)

const (
	csrHostname = "host1"
	csrCN       = "CN"
)

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
}