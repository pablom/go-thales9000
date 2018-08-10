package thales9000

import (
	"net"
	"bytes"
	"fmt"
	"crypto/rsa"
	"encoding/asn1"
	"crypto"
	"errors"
)

const (
	THALES_MSG_HEADER_LEN   int = 10
	THALES_RS_HEADER_LEN    int = 8
	THALES_HSM_HEADER		string = "HDR9"

	THALES_PUB_KEY_ENCODING_ASN1     string = "01"
	THALES_PUB_KEY_ENCODING_ASN2     string = "02"

	THALES_NO_HASH_SIGN    crypto.Hash = 70
)


var hashThalesType = map[crypto.Hash] string {
	crypto.SHA1:      	 "01",
	crypto.MD5:          "02",
	THALES_NO_HASH_SIGN: "04", // No Hash
	crypto.SHA224:       "05",
	crypto.SHA256:       "06",
	crypto.SHA384:       "07",
	crypto.SHA512:       "08",
}

// =============================================================================
//  Validate a Thales RSA public key
//  return mac 4 bytes and DER encoding for ASN.1 Public Key
//  (INTEGER uses 2's complement representation)
// =============================================================================
func thalesValidatePublicKey(conn net.Conn, pubBytes []byte) ([]byte,[]byte, error) {
	const rqMsgID = "EQ" // Request message ID
	const rsMsgID = "ER" // Response message ID

	// leave 4 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))
	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)
	b.Write(pubBytes)

	// Send request
	if err := sendThalesRequest(conn, b); err != nil {
		return nil, nil, err
	}
	// Try to read response
	if br, err := readThalesResponse(conn, []byte(rsMsgID)); err != nil {
		return nil, nil, err
	} else if len(br) != 0 {
		return nil, nil, fmt.Errorf("Thales: invalid response public key validation")
	}

	return  pubBytes[:4], pubBytes[4:], nil
}
// =============================================================================
//  Import a Public Key
//  return mac 4 bytes and DER encoding for ASN.1 Public Key
// =============================================================================
func thalesImportPublicKey(conn net.Conn, pubkeyBytes []byte) ([]byte,[]byte,error) {
	const rqMsgID = "EO" // Request message ID
	const rsMsgID = "EP" // Response message ID

	// leave 4 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))
	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)
	b.WriteString(THALES_PUB_KEY_ENCODING_ASN2)
	b.Write(pubkeyBytes)

	// Send request
	if err := sendThalesRequest(conn, b); err != nil {
		return nil, nil, err
	}
	// Try to read response
	br, err := readThalesResponse(conn, []byte(rsMsgID))
	if err != nil {
		return nil, nil, err
	}
	// Validate public key
	return thalesValidatePublicKey(conn, br)
}
// =============================================================================
//  Generate RSA signature
//  return mac 4 bytes and DER encoding for ASN.1 Public Key
// =============================================================================
func thalesGenerateRSASignature(conn net.Conn, msg []byte, privkeyBytes []byte, hashType crypto.Hash) ([]byte, error){
	const rqMsgID = "EW" // Request message ID
	const rsMsgID = "EX" // Response message ID

	htype, ok := hashThalesType[hashType]; if !ok {
		return nil, errors.New("thales9000: unknown hash function")
	}

	// leave 4 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))
	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)
	b.WriteString( htype ) // Hash type
	b.WriteString("01") // Identifier of the signature algorithm used to sign the message, RSA
	b.WriteString("01") // Identifier of the padding mode used in signature generation. '01' : PKCS#1 v1.5 method
	// Write message
	b.WriteString(fmt.Sprintf("%04d", len(msg)))
	b.Write(msg)
	b.WriteString(";")  // Delimiter, used to indicate the end of the message data field
	b.WriteString("99")
	b.Write(privkeyBytes)

/*
	if hashType == THALES_NO_HASH_SIGN {
		fmt.Println(hex.Dump(b.Bytes()))
	}
*/
	// Send request
	if err := sendThalesRequest(conn, b); err != nil {
		return nil, err
	}
	// Try to read response
	br, err := readThalesResponse(conn, []byte(rsMsgID))
	if err != nil {
		return nil, err
	}

	return br, nil
}
// =============================================================================
//  Validate a RSA signature
// =============================================================================
func thalesValidateSignatureRSA(conn net.Conn, msg []byte, sign []byte, mac []byte, pb []byte, hashType crypto.Hash) (error) {
	const rqMsgID = "EY" // Request message ID
	const rsMsgID = "EZ" // Response message ID

	 htype, ok := hashThalesType[hashType]; if !ok {
		return errors.New("thales9000: unknown hash function")
	}

	// leave 4 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))
	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)
	b.WriteString( htype ) // Hash type
	b.WriteString("01") // Identifier of the signature algorithm used to sign the message, RSA
	b.WriteString("01") // Identifier of the padding mode used in signature generation. '01' : PKCS#1 v1.5 method
	// Write signature
	b.Write(sign)
	b.WriteString(";")
	// Write message
	b.WriteString(fmt.Sprintf("%04d", len(msg)))
	b.Write(msg)
	b.WriteString(";")
	b.Write(mac)
	b.Write(pb)

	//if hashType == THALES_NO_HASH_SIGN {
	//	fmt.Println(hex.Dump(b.Bytes()))
	//}

	// Send request
	if err := sendThalesRequest(conn, b); err != nil {
		return err
	}
	// Try to read response
	_, err := readThalesResponse(conn, []byte(rsMsgID))
	if err != nil {
		return err
	}

	return nil
	//fmt.Println(hex.Dump(br.Bytes()[:rb]))
}
// =============================================================================
//  Generate a Public/Private Key Pair (internal function)
// =============================================================================
func thalesGenerateRSAKeyPairReq(conn net.Conn, rsaBits int) ([]byte, error) {
	const rqMsgID = "EI" // Request message ID
	const rsMsgID = "EJ" // Response message ID

	// leave 4 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))

	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)
	b.WriteString("0")         // Key Type indicator
	b.WriteString(fmt.Sprintf("%04d", rsaBits)) // Modulus length in bits
	b.WriteString(THALES_PUB_KEY_ENCODING_ASN2)

	// Send request
	if err := sendThalesRequest(conn, b); err != nil {
		return nil, err
	}
	// Try to read response
	br, err := readThalesResponse(conn, []byte(rsMsgID))
	if err != nil {
		return nil, err
	}

	return br, nil
}
// =============================================================================
//  Generate a Public/Private Key Pair
//  return Public Key ASN.1 DER bytes and 4 MAC bytes
// =============================================================================
func thalesGenerateRSAKeyPair(conn net.Conn, rsaBits int) ([]byte,[]byte,[]byte,error) {

	var pubKey rsa.PublicKey

	// Check RSA modulus length in bits, have to be between: 0320 ... 4096
	if rsaBits < 320 || rsaBits > 4096 {
		return nil, nil, nil, fmt.Errorf("Thales: Invalid RSA modulus length in bits")
	}

	// Try to generate RSA key pair
	 b, err := thalesGenerateRSAKeyPairReq(conn, rsaBits)
	 if err != nil {
		 return nil, nil, nil, err
	 }

	// Try to get first bytes as ASN.1 (public key)
	privBytes, err := asn1.Unmarshal(b, &pubKey)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(privBytes) == 0 {
		return nil, nil, nil, fmt.Errorf("Thales: invalid response (missed private key data)")
	}

	// Get public key bytes
	pb := b[:(len(b)-len(privBytes))]

	// Get real public key ASN.1 structure
	mac, pubBytes, err := thalesImportPublicKey(conn, pb)
	if err != nil {
		return nil, nil, nil, err
	}

	return mac, pubBytes, privBytes, nil
}
