package thales9000

import (
	"net"
	"fmt"
	"encoding/binary"
	"bytes"
	"crypto/x509"
	"io/ioutil"
	"encoding/pem"
	"math/big"
	"time"
	"crypto/rand"
	"os"
	"crypto/rsa"
	"crypto"
	"crypto/ecdsa"
)

// =============================================================================
//  Helper function to send Thales HSM request
// =============================================================================
func sendThalesRequest(conn net.Conn, b *bytes.Buffer) (error) {
	// Write message length to buffer request
	binary.BigEndian.PutUint16(b.Bytes(), uint16(b.Len() - 2))

	// send message to Thales HSM
	wb,err := conn.Write(b.Bytes())
	if err != nil {
		return err
	}

	if wb == 0 || wb != b.Len() {
		return fmt.Errorf("Thales connection: couldn't write all data to socket")
	}

	return nil
}
// =============================================================================
//  Helper function to get response from Thale HSM, validate response header,
//  message code and response code
// =============================================================================
func readThalesResponse(conn net.Conn, msgID []byte) ([]byte, error) {
	var b []byte

	// Allocate buffer for Thales message header
	bh := make([]byte, THALES_MSG_HEADER_LEN)
	// Try to read from socket connection
	rb, err := conn.Read(bh)
	if err != nil {
		return nil, err
	}

	if rb != THALES_MSG_HEADER_LEN {
		return nil, fmt.Errorf("Thales connection: invalid response length [%d], expected at least [%d]", rb, THALES_MSG_HEADER_LEN)
	}

	blen := binary.BigEndian.Uint16(bh[:2])

	if blen > (uint16)(THALES_RS_HEADER_LEN) {
		b = make([]byte, (int)(blen) - THALES_RS_HEADER_LEN)
		rb, err = conn.Read(b)
		if err != nil {
			return nil, err
		}

		if rb != (int)(blen) - THALES_RS_HEADER_LEN {
			return nil, fmt.Errorf("Thales connection: invalid response length [%d], expected [%d]", rb, (int)(blen) - THALES_RS_HEADER_LEN)
		}
	}

	// Check returned response message header
	if !bytes.Equal([]byte(THALES_HSM_HEADER), bh[2:][:4]) {
		return nil, fmt.Errorf("Thales connection: invalid response header [%s], expected [%s]", bh[2:][:4], THALES_HSM_HEADER)
	}

	// Check returned response message ID
	if !bytes.Equal(msgID,bh[6:][:2]) {
		return nil, fmt.Errorf("Thales connection: invalid response message id [%s], expected [%s]", bh[6:][:2], msgID)
	}

	if !bytes.Equal([]byte("00"), bh[8:][:2]) {
		return nil, fmt.Errorf("Thales connection: invalid rc [%s]", bh[8:][:2])
	}

	if len(b) > 0 {
		return b, nil
	}

	// Completed message received
	return nil, nil
}

func parsePrivateKey(der []byte) (crypto.PrivateKey, error) {
	if key, err := x509.ParsePKCS1PrivateKey(der); err == nil {
		return key, nil
	}
	if key, err := x509.ParsePKCS8PrivateKey(der); err == nil {
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("Found unknown private key type in PKCS#8 wrapping")
		}
	}
	if key, err := x509.ParseECPrivateKey(der); err == nil {
		return key, nil
	}
	return nil, fmt.Errorf("Failed to parse private key")
}

func CsrToCrt( caCrtFile string, caKeyFile string, csrFile, outCrtFile string, password string ) error {

	//var caPrivateKey *rsa.PrivateKey

	// load CA key pair public key
	caPublicKeyFile, err := ioutil.ReadFile(caCrtFile)
	if err != nil {
		return err
	}
	pemBlock, _ := pem.Decode(caPublicKeyFile)
	if pemBlock == nil {
		return fmt.Errorf("pem.Decode failed")
	}
	caCRT, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return err
	}

	//  private key
	caPrivateKeyFile, err := ioutil.ReadFile(caKeyFile)
	if err != nil {
		return err
	}
	pemBlock, _ = pem.Decode(caPrivateKeyFile)
	if pemBlock == nil {
		return fmt.Errorf("pem.Decode failed")
	}

	parseResult, err := parsePrivateKey(pemBlock.Bytes)
	caPrivateKey := parseResult.(*rsa.PrivateKey)

/*
	// No password
	if len(password) == 0 {
		caPrivateKey, err = x509.ParsePKCS1PrivateKey(pemBlock.Bytes)
		if err != nil {
			return fmt.Errorf("x509.ParsePKCS1PrivateKey: %s",err)
			//return err
		}
	} else {
		der, err := x509.DecryptPEMBlock(pemBlock, []byte(password))
		if err != nil {
			return fmt.Errorf("x509.DecryptPEMBlock: %s",err)
			//return err
		}

		caPrivateKey, err = x509.ParsePKCS1PrivateKey(der)
		if err != nil {
			return err
		}
	}
*/

	// load client certificate request
	clientCSRFile, err := ioutil.ReadFile(csrFile)
	if err != nil {
		return err
	}
	pemBlock, _ = pem.Decode(clientCSRFile)
	if pemBlock == nil {
		return fmt.Errorf("pem.Decode failed")
	}
	clientCSR, err := x509.ParseCertificateRequest(pemBlock.Bytes)
	if err != nil {
		return err
	}
	if err = clientCSR.CheckSignature(); err != nil {
		return err
	}

	// create client certificate template
	clientCRTTemplate := x509.Certificate{
		Signature:          clientCSR.Signature,
		SignatureAlgorithm: clientCSR.SignatureAlgorithm,

		PublicKeyAlgorithm: clientCSR.PublicKeyAlgorithm,
		PublicKey:          clientCSR.PublicKey,

		SerialNumber: big.NewInt(7),
		Issuer:       caCRT.Subject,
		Subject:      clientCSR.Subject,
		// NotBefore is set to be 10min earlier to fix gap on time difference in cluster
		NotBefore:    time.Now().Add(-600).UTC(),
		//NotAfter:     time.Now().Add(24 * time.Hour),
		NotAfter:     caCRT.NotAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	// create client certificate from template and CA public key
	clientCRTRaw, err := x509.CreateCertificate(rand.Reader, &clientCRTTemplate, caCRT, clientCSR.PublicKey, caPrivateKey)
	if err != nil {
		return err
	}

	// save the certificate
	clientCRTFile, err := os.Create(outCrtFile)
	if err != nil {
		return err
	}
	pem.Encode(clientCRTFile, &pem.Block{Type: "CERTIFICATE", Bytes: clientCRTRaw})
	clientCRTFile.Close()
	return nil
}