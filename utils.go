package thales9000

import (
	"net"
	"fmt"
	"encoding/binary"
	"bytes"
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