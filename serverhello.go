package twiddle

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"errors"
)

// Synthesising the server's opening.
//
// Measured against www.google.com, www.cloudflare.com and www.microsoft.com,
// the ServerHello record is 1210 bytes on all three -- a number set almost
// entirely by the X25519MLKEM768 key share, whose server-side value is a
// 1088-byte ML-KEM ciphertext followed by a 32-byte X25519 key. Every captured
// Chrome hello offers that group, and every modern server selects it, so
// selecting anything else would itself be the anomaly.
//
// Under theater the ML-KEM half never has to be real: it is opaque bytes to any
// observer, and both ends of the connection are ours. What must be right is what
// a censor can actually check -- the group id, the total length, and the
// structure around them. The real key agreement rides in the X25519 half.

const (
	// GroupX25519MLKEM768 is the hybrid every modern server selects.
	GroupX25519MLKEM768 uint16 = 0x11ec

	mlkem768CiphertextLen = 1088
	hybridServerShareLen  = mlkem768CiphertextLen + 32

	TLS_AES_128_GCM_SHA256 uint16 = 0x1301
	TLS_AES_256_GCM_SHA384 uint16 = 0x1302
)

// ServerHelloParams describes the opening a server synthesises in reply.
type ServerHelloParams struct {
	// SessionIDEcho MUST be the client's legacy_session_id. TLS 1.3 requires the
	// echo, which means an authenticator placed in session_id would appear twice
	// on the wire -- one reason the ticket is the better carrier.
	SessionIDEcho []byte
	CipherSuite   uint16
	// ServerEphemeral is the X25519 half of the hybrid key share.
	ServerEphemeral *ecdh.PublicKey
	// SelectedIdentity is the PSK the server accepted; 0 for the only one we offer.
	SelectedIdentity uint16
}

// SynthesizeServerHello builds the ServerHello handshake record.
func SynthesizeServerHello(p ServerHelloParams) ([]byte, error) {
	if len(p.SessionIDEcho) == 0 || len(p.SessionIDEcho) > 32 {
		return nil, errors.New("twiddle: session_id echo must be 1..32 bytes")
	}
	if p.ServerEphemeral == nil {
		return nil, errors.New("twiddle: no server ephemeral")
	}
	suite := p.CipherSuite
	if suite == 0 {
		suite = TLS_AES_128_GCM_SHA256
	}

	// The ML-KEM ciphertext is indistinguishable from random to an observer and
	// carries nothing: the real agreement is the X25519 key appended after it.
	share := make([]byte, hybridServerShareLen)
	if _, err := rand.Read(share[:mlkem768CiphertextLen]); err != nil {
		return nil, err
	}
	copy(share[mlkem768CiphertextLen:], p.ServerEphemeral.Bytes())

	var ext []byte
	ext = appendU16(ext, 0x002b) // supported_versions
	ext = appendU16(ext, 2)
	ext = appendU16(ext, 0x0304) // TLS 1.3

	ext = appendU16(ext, ExtKeyShare)
	ext = appendU16(ext, uint16(4+len(share)))
	ext = appendU16(ext, GroupX25519MLKEM768)
	ext = appendU16(ext, uint16(len(share)))
	ext = append(ext, share...)

	ext = appendU16(ext, ExtPreSharedKey)
	ext = appendU16(ext, 2)
	ext = appendU16(ext, p.SelectedIdentity)

	var body []byte
	body = appendU16(body, 0x0303) // legacy_version
	random := make([]byte, 32)
	if _, err := rand.Read(random); err != nil {
		return nil, err
	}
	body = append(body, random...)
	body = append(body, byte(len(p.SessionIDEcho)))
	body = append(body, p.SessionIDEcho...)
	body = appendU16(body, suite)
	body = append(body, 0x00) // legacy_compression_method
	body = appendU16(body, uint16(len(ext)))
	body = append(body, ext...)

	out := make([]byte, 0, len(body)+9)
	out = append(out, 0x16, 0x03, 0x03)
	out = appendU16(out, uint16(len(body)+4))
	out = append(out, 0x02, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	return append(out, body...), nil
}

// ChangeCipherSpec is the one-byte compatibility record both sides send.
func ChangeCipherSpec() []byte { return []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01} }

// ServerEphemeralFromShare extracts the X25519 half from a synthesised hybrid
// server key share.
func ServerEphemeralFromShare(sh []byte) (*ecdh.PublicKey, error) {
	h, err := parseServerHelloExtensions(sh)
	if err != nil {
		return nil, err
	}
	share, ok := h[ExtKeyShare]
	if !ok || len(share) < 4 {
		return nil, errors.New("twiddle: ServerHello has no key_share")
	}
	n := int(binary.BigEndian.Uint16(share[2:4]))
	if 4+n > len(share) || n < 32 {
		return nil, errMalformed
	}
	return ecdh.X25519().NewPublicKey(share[4+n-32 : 4+n])
}

func parseServerHelloExtensions(rec []byte) (map[uint16][]byte, error) {
	if len(rec) < 9 || rec[0] != 0x16 || rec[5] != 0x02 {
		return nil, errors.New("twiddle: not a ServerHello record")
	}
	b := rec[9:]
	p := 2 + 32
	if p >= len(b) {
		return nil, errMalformed
	}
	p += 1 + int(b[p]) // session_id echo
	p += 2 + 1         // cipher_suite, compression
	if p+2 > len(b) {
		return nil, errMalformed
	}
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:p+2]))
	p += 2
	out := map[uint16][]byte{}
	for p+4 <= end && p+4 <= len(b) {
		t := binary.BigEndian.Uint16(b[p : p+2])
		n := int(binary.BigEndian.Uint16(b[p+2 : p+4]))
		if p+4+n > len(b) {
			return nil, errMalformed
		}
		out[t] = b[p+4 : p+4+n]
		p += 4 + n
	}
	return out, nil
}
