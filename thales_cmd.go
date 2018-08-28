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
	crypto.SHA1:         "01",
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

	// leave 2 bytes at the start for length
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
		return nil, nil, fmt.Errorf("thales9000: invalid response public key validation")
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

	// leave 2 bytes at the start for length
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

	// leave 2 bytes at the start for length
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

	// leave 2 bytes at the start for length
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
func thalesGenerateRSAKeyPairReq(conn net.Conn, rsaBits int, keyType int) ([]byte, error) {
	const rqMsgID = "EI" // Request message ID
	const rsMsgID = "EJ" // Response message ID

	// leave 2 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))

	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)
	b.WriteString(fmt.Sprintf("%1d", keyType)) // Key Type indicator
	                   //   '0' : Signature only
	                   //   '1' : Key management only
	                   //   '2' : Both signature and key management
	                   //   '3' : Integrated Chip Card (ICC) Key
	                   //   '4' : allows general purpose decryption of data (e.g. TLS/SSL  premaster secret) – requires HSM9-LIC019
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
func thalesGenerateRSAKeyPair(conn net.Conn, rsaBits int, keyType int) ([]byte,[]byte,[]byte,error) {

	var pubKey rsa.PublicKey

	// Check RSA modulus length in bits, have to be between: 0320 ... 4096
	if rsaBits < 320 || rsaBits > 4096 {
		return nil, nil, nil, fmt.Errorf("thales9000: Invalid RSA modulus length in bits")
	}

	// Try to generate RSA key pair
	 b, err := thalesGenerateRSAKeyPairReq(conn, rsaBits, keyType)
	 if err != nil {
		 return nil, nil, nil, err
	 }

	// Try to get first bytes as ASN.1 (public key)
	privBytes, err := asn1.Unmarshal(b, &pubKey)
	if err != nil {
		return nil, nil, nil, err
	}

	if len(privBytes) == 0 {
		return nil, nil, nil, fmt.Errorf("thales9000: invalid response (missed private key data)")
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
// =============================================================================
//  Perform Thales diagnostics command
// =============================================================================
func thalesDiagnostics(conn net.Conn) ([]byte,error) {
	const rqMsgID = "NC" // Request message ID
	const rsMsgID = "ND" // Response message ID
	// leave 2 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))
	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)

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
//  Generate new key
// =============================================================================
func thalesGenerateSymmetricKey(conn net.Conn) ([]byte,error) {
	const rqMsgID = "A0" // Request message ID
	const rsMsgID = "A1" // Response message ID
	// leave 2 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))
	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)
	b.WriteString("0")    // Generate key
	b.WriteString("008")
	b.WriteString("U")

	// Send request
	if err := sendThalesRequest(conn, b); err != nil {
		return nil, err
	}
	// Try to read response
	br, err := readThalesResponse(conn, []byte(rsMsgID))
	if err != nil {
		return nil, err
	}

	//fmt.Println(hex.Dump(br))

	return br, nil
}
// =============================================================================
//  Generate MAC
// =============================================================================
func thalesGenerateMAC(conn net.Conn, msg []byte, key string) ([]byte,error) {
	const rqMsgID = "M6" // Request message ID
	const rsMsgID = "M7" // Response message ID
	// leave 2 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))
	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)
	b.WriteString("0")    // Only block of a single-block message
	b.WriteString("0")    // Input Format Flag: binary
	b.WriteString("1")    // MAC size, '0' : MAC size of 8 hex digits,  '1' : MAC size of 16 hex digits
	b.WriteString("3")    // ISO 9797 MAC algorithm 3 (= ANSI X9.19 when used with a double-length key) (DES only)
	b.WriteString("0")    // 0' : No padding
	b.WriteString("008")  // ZAK key type
	b.WriteString(key)
	b.WriteString(fmt.Sprintf("%04X", len(msg)))
	b.Write(msg)

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
//  Verify MAC
// =============================================================================
func thalesVerifyMAC(conn net.Conn, msg []byte, mac, key string) ([]byte,error) {
	const rqMsgID = "M8" // Request message ID
	const rsMsgID = "M9" // Response message ID
	// leave 2 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))
	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)
	b.WriteString("0")    // Only block of a single-block message
	b.WriteString("0")    // Input Format Flag: binary
	b.WriteString("1")    // MAC size, '0' : MAC size of 8 hex digits,  '1' : MAC size of 16 hex digits
	b.WriteString("3")    // ISO 9797 MAC algorithm 3 (= ANSI X9.19 when used with a double-length key) (DES only)
	b.WriteString("0")    // 0' : No padding
	b.WriteString("008")  // ZAK key type
	b.WriteString(key)
	b.WriteString(fmt.Sprintf("%04X", len(msg)))
	b.Write(msg)
	b.WriteString(mac)

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
//  Encrypt Data Block
// =============================================================================
func thalesEncryptDataBlock(conn net.Conn, msg []byte, key string) ([]byte,error) {
	const rqMsgID = "M0" // Request message ID
	const rsMsgID = "M1" // Response message ID
	// leave 2 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))
	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)
	b.WriteString("00")  // encryption mode ECB
	b.WriteString("0")   // format of the input message: Binary
	b.WriteString("0")   // output format: Binary
	b.WriteString("00A")
	b.WriteString(key)
	b.WriteString(fmt.Sprintf("%04X", len(msg)))
	b.Write(msg)

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
//  Decrypt Data Block
// =============================================================================
func thalesDecryptDataBlock(conn net.Conn, data []byte, key string) ([]byte,error) {
	const rqMsgID = "M2" // Request message ID
	const rsMsgID = "M3" // Response message ID
	// leave 2 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))
	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)
	b.WriteString("00")  // encryption mode ECB
	b.WriteString("0")   // format of the input message: Binary
	b.WriteString("0")   // output format: Binary
	b.WriteString("00A")
	b.WriteString(key)
	b.WriteString(fmt.Sprintf("%04X", len(data)))
	b.Write(data)

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
// Import Key or data under an RSA Public Key
// =============================================================================
func thalesDecryptDataBlockRSA(conn net.Conn, data []byte, privKey []byte) ([]byte,error) {
	const rqMsgID = "GI" // Request message ID
	const rsMsgID = "GJ" // Response message ID
	// leave 2 bytes at the start for length
	b := bytes.NewBuffer(make([]byte, 2 ))
	b.WriteString(THALES_HSM_HEADER)
	b.WriteString(rqMsgID)
	b.WriteString("01")   // Identifier of algorithm used to decrypt the key: '01' : RSA
	b.WriteString("01")   // Identifier of the Pad Mode used in the encryption process 01 : PKCS#1 v1.5 method (EME-PKCS1-v1_5)
	b.WriteString("3400") // Key Type For data (e.g. TLS/SSL premaster) decryption with RSA Key
							 //Type Indicator '04' (requires LIC019), Key Type should have the value '3400'
	b.WriteString(fmt.Sprintf("%04d", len(data)))
	b.Write(data)
	b.WriteString(";")    // Delimiter
	b.WriteString("99")
	b.Write(privKey)

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