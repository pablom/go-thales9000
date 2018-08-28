package main

import (
	"fmt"
	"runtime"
	"os"
	"net"
	"time"
	"gopkg.in/alecthomas/kingpin.v2"
	//"github.com/pablom/go-thales9000"
	"../../go-thales9000"
	"io/ioutil"
)

const (
	HSM_CONNECTION_TIMEOUT   int64  = 2
)

var (
	version              = "v0.0.1"

	app = kingpin.New("thales9000-tool", "OpenWay Thales 9000 utility to prepare work with pkcs11 shared library.")

	keyRequestCommand = app.Command("keyreq", "RSA private key generate request")
	hsmKeyAddress  = keyRequestCommand.Flag("hsm", "Address and port of Thales 9000 HSM (HOST:PORT).").PlaceHolder("ADDR").Required().String()

	certRequestCommand = app.Command("certreq", "Certificate request generate")
	hsmCertAddress  = certRequestCommand.Flag("hsm", "Address and port of Thales 9000 HSM (HOST:PORT).").PlaceHolder("ADDR").Required().String()
	newKeyReq     = certRequestCommand.Flag("newkey", "If set, new one private key will be generated.").Default("False").Bool()
	certCN        = certRequestCommand.Flag("cert-cn", "New certificate common name. Default: CN").PlaceHolder("CN").Default("CN").String()
	certO         = certRequestCommand.Flag("cert-o", "New certificate organizational name. Default: OpenWay").PlaceHolder("O").Default("OpenWay").String()
	certOU        = certRequestCommand.Flag("cert-ou", "New certificate organizational unit name. Default: Development").PlaceHolder("OU").Default("Development").String()
	certCountry   = certRequestCommand.Flag("cert-country", "New certificate country name. Default: RU").PlaceHolder("CU").Default("RU").String()
	certHostName  = certRequestCommand.Flag("cert-host", "New certificate host name. Default: host").PlaceHolder("HOST").Default("host").String()
	certLocality  = certRequestCommand.Flag("cert-city", "New certificate locality name.").PlaceHolder("HOST").Default("Saint-Petersburg").String()
	certProvince  = certRequestCommand.Flag("cert-state", "New certificate province name. Default: Russia").PlaceHolder("HOST").Default("Russia").String()
	certReqFileName = certRequestCommand.Flag("cert-csr", "New certificate request file name. Default: cert.csr").PlaceHolder("FileName").Default("cert.csr").String()
	certFileName    = certRequestCommand.Flag("cert-crt", "New certificate ouput file name signing by CA. Default: cert.crt").PlaceHolder("FileName").Default("cert.crt").String()

	caCertPath    = certRequestCommand.Flag("cacert", "Path to CA certificate file (PEM/X509). Uses only to generate certificate from certificate request for local testing.").String()
	caPrivKeyPath = certRequestCommand.Flag("cakey", "Path to CA private key file (PEM). Uses only to generate certificate from certificate request for local testing.").String()

	keySize  = app.Flag("keysize", "RSA key size in bits. Default: 1024").PlaceHolder("SIZE").Default("1024").Int()
	keyType  = app.Flag("keytype", "RSA key type. Default: 4 (allow TLS/SSL)\nAvailable: 0 - only allow signing").PlaceHolder("TYPE").Default("4").Int()

	privateKeyFileName = app.Flag("private-key", "File name to save/load private key data. Default: priv_key.bin").PlaceHolder("FileName").Default("priv_key.bin").String()
	publicKeyFileName = app.Flag("public-key", "File name to save/load public key. Default: public_key.pem").PlaceHolder("FileName").Default("public_key.pem").String()
	confPath  = app.Flag("confpath", "Path to certificate and private key data store (PEM certificate and public key)." +
		"This parameter can be set from the environment variable 'PKCS11_THALES_9000_CONF_DIR'. " +
		"If this parameter is empty, all data will be saved to the current folder.").PlaceHolder("PATH").String()
)
//==================================================================================
//  Validate flags for both commands
//==================================================================================
func validateFlags(app *kingpin.Application) error {
	// Redefine configuration path
	if *confPath == "" {
		*confPath = os.Getenv("PKCS11_THALES_9000_CONF_DIR")
	}

	return nil
}
//==================================================================================
func keyReqValidateFlags() error {
	return nil
}
//==================================================================================
func certValidateFlags() error {
	return nil
}
//==================================================================================
//  Private /public key command
//==================================================================================
func keyCreateCmd( hsmTcpIpAddress string) *thales9000.RsaThalesPrivKey {

	conn, err := net.DialTimeout("tcp", hsmTcpIpAddress, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr,"[ERROR]: Failed to HSM connect: %s\n", err)
	}
	defer conn.Close()

	key, err := thales9000.CreateRSAKey(conn, *keySize, *keyType)
	if err != nil {
		fmt.Fprintf(os.Stderr,"[ERROR]: Failed creating rsa key pair: %s\n", err)
		return nil
	}

	var pivateKeyPath string
	var publicKeyPath string

	if *confPath == "" {
		pivateKeyPath = *privateKeyFileName
		publicKeyPath = *publicKeyFileName
	} else {
		pivateKeyPath = *confPath + "/" + *privateKeyFileName
		publicKeyPath = *confPath + "/" + *publicKeyFileName
	}

	if err = key.WritePrivateKeyToFile(pivateKeyPath); err != nil {
		fmt.Fprintf(os.Stderr,"[ERROR]: Failed create thales rsa private key file:", err)
		return nil
	}

	if err = key.WritePublicKeyToFile(publicKeyPath); err != nil {
		fmt.Fprintf(os.Stderr,"[ERROR]: Failed create thales rsa public key file:", err)
		return nil
	}

	return key
}
//==================================================================================
//  Certificate request command
//==================================================================================
func certificateRequestCreateCmd() {
	conn, err := net.DialTimeout("tcp", *hsmCertAddress, time.Duration(HSM_CONNECTION_TIMEOUT)*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr,"[ERROR]: Failed to HSM connect: %s\n", err)
	}
	defer conn.Close()

	var pk *thales9000.RsaThalesPrivKey

	if *newKeyReq {
		if pk = keyCreateCmd(*hsmCertAddress); pk == nil {
			return
		}
	}

	var pivateKeyPath string
	var publicKeyPath string
	var certReqPath string
	var certPath string

	if *confPath == "" {
		pivateKeyPath = *privateKeyFileName
		publicKeyPath = *publicKeyFileName
		certReqPath = *certReqFileName
		certPath = *certFileName
	} else {
		pivateKeyPath = *confPath + "/" + *privateKeyFileName
		publicKeyPath = *confPath + "/" + *publicKeyFileName
		certReqPath = *confPath + "/" + *certReqFileName
		certPath = *confPath + "/" + *certFileName
	}

	if _, err := os.Stat(pivateKeyPath); err == nil {
		if _, err := os.Stat(publicKeyPath); err == nil {
			if pk, err = thales9000.NewThalesPrivKeyFromFiles(publicKeyPath, pivateKeyPath, conn); err != nil {
				fmt.Fprintf(os.Stderr,"[ERROR]: Couldn't load private key data: %s\n", err)
			}
		}
	}

	csr, err := thales9000.CreateCertificateSigningRequest(pk, *certO, nil, nil,
		*certOU, *certCountry, *certProvince, *certLocality, *certCN)

	if err != nil {
		fmt.Fprintf(os.Stderr,"[ERROR] Failed creating certificate request: %s\n", err)
		return
	}

	if err = csr.CheckSignature(); err != nil {
		fmt.Fprintf(os.Stderr,"[ERROR] Failed checking signature in certificate request: %s\n", err)
		return
	}

	// Export certificate request to file
	b, err := csr.Export()
	if err != nil {
		fmt.Fprintf(os.Stderr,"[ERROR] Failed to export certificate request as pem bytes: %s\n", err)
		return
	}

	err = ioutil.WriteFile(certReqPath, b, 0644)
	if err != nil {
		fmt.Fprintf(os.Stderr,"[ERROR] Failed export to file certificate request: %s\n", err)
		return
	}

	if *caCertPath != "" && *caPrivKeyPath != "" {
		err = thales9000.CsrToCrt(*caCertPath, *caPrivKeyPath, certReqPath, certPath, "")
		if err != nil {
			fmt.Fprintf(os.Stderr,"[ERROR] Failed to get test certificate from certificate request: %s\n", err)
		}
	}
}
//==================================================================================
//  Main entry point
//==================================================================================
func main() {

	app.Version(fmt.Sprintf("%s built with %s", version, runtime.Version()))
	app.Validate(validateFlags)
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	switch command {
	case keyRequestCommand.FullCommand():
		if err := keyReqValidateFlags(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return
		}
		// Create RSA key
		keyCreateCmd(*hsmKeyAddress)
		return

	case certRequestCommand.FullCommand():
		if err := certValidateFlags(); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %s\n", err)
			return
		}
		certificateRequestCreateCmd()
		return
	}

	fmt.Fprintf(os.Stderr, "Error: unknown command\n")
}