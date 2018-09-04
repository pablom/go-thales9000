package main

import (
	"fmt"
	"runtime"
	"os"
	"gopkg.in/alecthomas/kingpin.v2"
)

const (
	HSM_CONNECTION_TIMEOUT   int64  = 2
)

var (
	version = "v0.0.1"

	app = kingpin.New("thales9000-tool", "OpenWay Thales 9000 utility to prepare work with pkcs11 shared library.")
	cfgFilePath = app.Flag("config", "Configuration file path").PlaceHolder("PATH").Required().String()
	genKeyCmd = app.Command("genkey", "generate a new Thales private key and certificate request")

	confPkcs11Path  = app.Flag("confpath", "Path to certificate and private key data store (PEM certificate and public key)." +
		"This parameter can be set from the environment variable 'PKCS11_THALES_9000_CONF_DIR'. " +
		"If this parameter is empty, all data will be saved to the current folder.").PlaceHolder("PATH").String()
)
//==================================================================================
//  Validate flags for all commands
//==================================================================================
func validateFlags(app *kingpin.Application) error {
	// Redefine configuration path
	if *confPkcs11Path == "" {
		*confPkcs11Path = os.Getenv("PKCS11_THALES_9000_CONF_DIR")
	}
	return nil
}
//==================================================================================
//  Main entry point
//==================================================================================
func main() {

	app.Version(fmt.Sprintf("%s built with %s", version, runtime.Version()))
	app.Validate(validateFlags)
	command := kingpin.MustParse(app.Parse(os.Args[1:]))

	switch command {
	case genKeyCmd.FullCommand():
		genkeyCmd()
		return
	}

	fmt.Fprintf(os.Stderr, "Error: unknown command\n")
}