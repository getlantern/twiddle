// Package twiddle implements a TLS-shaped transport whose opening bytes are a
// genuine ClientHello harvested from a real browser, minimally modified.
package twiddle

import (
	"encoding/binary"
	"errors"
	"fmt"
)

// Extension is a ClientHello extension held as raw bytes.
//
// Extensions are deliberately NOT decoded into typed structures. That is the
// difference between this and a TLS library's hello builder: a typed parser
// drops or normalises extensions it does not recognise, so re-serialising loses
// fidelity the moment a browser ships something new. Chrome sends at least one
// extension no Go TLS library models (server_padding, 0x12e0), and will send
// more. Holding them opaque means Marshal reproduces the input byte for byte.
type Extension struct {
	Type uint16
	Data []byte
}

// ClientHello is a parsed but not interpreted TLS ClientHello record.
type ClientHello struct {
	LegacyVersion uint16
	Random        [32]byte
	SessionID     []byte
	CipherSuites  []uint16
	Compression   []byte
	Extensions    []Extension
}

const (
	ExtServerName    uint16 = 0x0000
	ExtSessionTicket uint16 = 0x0023
	ExtPreSharedKey  uint16 = 0x0029
	ExtKeyShare      uint16 = 0x0033
	ExtECH           uint16 = 0xfe0d
	ExtServerPadding uint16 = 0x12e0
)

var errMalformed = errors.New("twiddle: malformed ClientHello")

// IsGREASE reports whether an extension type or named value is a GREASE
// placeholder (RFC 8701): both bytes equal and of the form 0x?a0?a.
func IsGREASE(v uint16) bool {
	return v&0x0f0f == 0x0a0a && byte(v>>8) == byte(v)
}

type reader struct {
	b   []byte
	i   int
	err error
}

func (r *reader) u8() int {
	if r.err != nil || r.i+1 > len(r.b) {
		r.err = errMalformed
		return 0
	}
	v := int(r.b[r.i])
	r.i++
	return v
}

func (r *reader) u16() int {
	if r.err != nil || r.i+2 > len(r.b) {
		r.err = errMalformed
		return 0
	}
	v := int(binary.BigEndian.Uint16(r.b[r.i : r.i+2]))
	r.i += 2
	return v
}

func (r *reader) bytes(n int) []byte {
	if r.err != nil || n < 0 || r.i+n > len(r.b) {
		r.err = errMalformed
		return nil
	}
	v := r.b[r.i : r.i+n]
	r.i += n
	return v
}

// ParseClientHello parses a complete TLS handshake record containing a
// ClientHello. rec includes the 5-byte record header.
func ParseClientHello(rec []byte) (*ClientHello, error) {
	if len(rec) < 9 || rec[0] != 0x16 {
		return nil, fmt.Errorf("twiddle: not a handshake record")
	}
	if n := int(binary.BigEndian.Uint16(rec[3:5])); len(rec) != 5+n {
		return nil, fmt.Errorf("twiddle: record length %d does not match %d bytes", n, len(rec)-5)
	}
	r := &reader{b: rec[5:]}
	if r.u8() != 0x01 {
		return nil, fmt.Errorf("twiddle: not a ClientHello")
	}
	bodyLen := r.u8()<<16 | r.u16()
	if bodyLen != len(r.b)-4 {
		return nil, fmt.Errorf("twiddle: handshake length %d does not match %d bytes", bodyLen, len(r.b)-4)
	}

	h := &ClientHello{}
	h.LegacyVersion = uint16(r.u16())
	copy(h.Random[:], r.bytes(32))
	h.SessionID = append([]byte(nil), r.bytes(r.u8())...)

	csLen := r.u16()
	if csLen%2 != 0 {
		return nil, errMalformed
	}
	cs := r.bytes(csLen)
	for i := 0; i+2 <= len(cs); i += 2 {
		h.CipherSuites = append(h.CipherSuites, binary.BigEndian.Uint16(cs[i:i+2]))
	}
	h.Compression = append([]byte(nil), r.bytes(r.u8())...)

	extTotal := r.u16()
	end := r.i + extTotal
	for r.i < end && r.err == nil {
		t := uint16(r.u16())
		d := r.bytes(r.u16())
		h.Extensions = append(h.Extensions, Extension{t, append([]byte(nil), d...)})
	}
	if r.err != nil {
		return nil, r.err
	}
	if r.i != len(r.b) {
		return nil, fmt.Errorf("twiddle: %d trailing bytes after extensions", len(r.b)-r.i)
	}
	return h, nil
}

// Marshal rebuilds the complete handshake record. Every length field is
// recomputed, so callers may change any field without tracking the five nested
// lengths (extension, extension block, hello body, handshake message, record).
func (h *ClientHello) Marshal() []byte {
	var ext []byte
	for _, e := range h.Extensions {
		ext = appendU16(ext, e.Type)
		ext = appendU16(ext, uint16(len(e.Data)))
		ext = append(ext, e.Data...)
	}

	var body []byte
	body = appendU16(body, h.LegacyVersion)
	body = append(body, h.Random[:]...)
	body = append(body, byte(len(h.SessionID)))
	body = append(body, h.SessionID...)
	body = appendU16(body, uint16(len(h.CipherSuites)*2))
	for _, c := range h.CipherSuites {
		body = appendU16(body, c)
	}
	body = append(body, byte(len(h.Compression)))
	body = append(body, h.Compression...)
	body = appendU16(body, uint16(len(ext)))
	body = append(body, ext...)

	out := make([]byte, 0, len(body)+9)
	out = append(out, 0x16, 0x03, 0x01)
	out = appendU16(out, uint16(len(body)+4))
	out = append(out, 0x01, byte(len(body)>>16), byte(len(body)>>8), byte(len(body)))
	return append(out, body...)
}

func appendU16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }

// Find returns the first extension of the given type, or nil.
func (h *ClientHello) Find(t uint16) *Extension {
	for i := range h.Extensions {
		if h.Extensions[i].Type == t {
			return &h.Extensions[i]
		}
	}
	return nil
}

// SNI returns the server name, or "" if the extension is absent or empty.
func (h *ClientHello) SNI() string {
	e := h.Find(ExtServerName)
	if e == nil || len(e.Data) < 5 {
		return ""
	}
	n := int(binary.BigEndian.Uint16(e.Data[3:5]))
	if 5+n > len(e.Data) {
		return ""
	}
	return string(e.Data[5 : 5+n])
}

// SetSNI replaces the server name. Length changes cascade automatically through
// Marshal; nothing in a modern Chrome hello absorbs the delta (no padding
// extension is sent, and ECH GREASE length was measured independent of SNI
// length), so hellos of different SNI length legitimately differ in total size.
func (h *ClientHello) SetSNI(name string) error {
	e := h.Find(ExtServerName)
	if e == nil {
		return errors.New("twiddle: hello has no server_name extension")
	}
	if len(name) > 0xffff-5 {
		return errors.New("twiddle: server name too long")
	}
	d := make([]byte, 0, 5+len(name))
	d = appendU16(d, uint16(len(name)+3)) // ServerNameList length
	d = append(d, 0x00)                   // name_type: host_name
	d = appendU16(d, uint16(len(name)))
	e.Data = append(d, name...)
	return nil
}
