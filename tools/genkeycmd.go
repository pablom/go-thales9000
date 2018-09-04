package main

import (
	"io/ioutil"
	"encoding/json"
	"fmt"
	"os"
	"net"
	"time"
	"crypto"
	"strings"
	"../../go-thales9000"
)


func genkeyCmd() {
	// Read configuration file
	cfgFileBytes, err := ioutil.ReadFile(*cfgFilePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR]: %s\n", err)
		return
	}
	// Create certificate request type object
	req := CertificateRequest{
		KeyRequest: NewBasicKeyRequest(),
	}
	// Read configuration from file
	if err = json.Unmarshal(cfgFileBytes, &req); err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR]: %s\n", err)
		return
	}
	// Try to Thales HSM connect
	conn, err := net.DialTimeout("tcp", req.HsmAddress, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr,"[ERROR]: Failed connect to Thales HSM: %s\n", err)
	}

	defer conn.Close()

	fmt.Fprintf(os.Stdout,"Generating Thales private key: %s-%d-%d", req.KeyRequest.Algo(), req.KeyRequest.Size(), req.KeyRequest.Type())
	priv, err := req.KeyRequest.Generate(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\n[ERROR]: %s\n", err)
		return
	}

	fmt.Fprintf(os.Stdout," [Done]\n");

	csrPEM, err := GenerateCSR(priv.(crypto.Signer), &req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "[ERROR]: %s\n", err)
		return
	}

	empty := func(s string) bool { return strings.TrimSpace(s) == "" }

	if empty(req.CsrFilePath) {
		fmt.Printf("\n%s\n", string(csrPEM))
	} else {
		ioutil.WriteFile(req.CsrFilePath, csrPEM, 0600)
	}
	// Save private & public keys
	req.KeyRequest.Save( priv.(*thales9000.RsaThalesPrivKey))
}
