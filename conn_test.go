package twiddle

import (
	"bytes"
	"testing"
)

// testTranscript is a fixed stand-in for the opening, for tests that only need
// two Sessions whose keys agree. DeriveSession refuses an empty transcript, so
// there is no unbound derivation anywhere -- including in tests, where one
// would quietly become the example everyone copies.
func testTranscript() []byte { return []byte("twiddle test transcript") }

func TestDeriveSessionBindsChangeCipherSpecPayload(t *testing.T) {
	// Fixed hello payloads isolate key derivation from handshake parsing. An
	// altered CCS value is rejected by Client before it reaches this layer.
	clientHello := []byte{0x16, 0x03, 0x01, 0, 4, 1, 0, 0, 0}
	serverHello := []byte{0x16, 0x03, 0x03, 0, 4, 2, 0, 0, 0}
	ccs := ChangeCipherSpec()
	alteredCCS := bytes.Clone(ccs)
	alteredCCS[recordHeaderLen] ^= 0x01
	for _, tc := range []struct {
		name  string
		suite uint16
	}{
		{"AES128_SHA256", TLS_AES_128_GCM_SHA256},
		{"AES256_SHA384", TLS_AES_256_GCM_SHA384},
	} {
		t.Run(tc.name, func(t *testing.T) {
			derive := func(record []byte) *Session {
				t.Helper()
				s, err := DeriveSession(make([]byte, 32), make([]byte, 32), tc.suite,
					Transcript(clientHello, serverHello, record))
				if err != nil {
					t.Fatal(err)
				}
				return s
			}
			original, altered := derive(ccs), derive(alteredCCS)
			for _, direction := range []struct {
				name              string
				original, altered Keys
			}{
				{"client", original.Client, altered.Client},
				{"server", original.Server, altered.Server},
			} {
				if bytes.Equal(direction.original.Key, direction.altered.Key) {
					t.Errorf("%s key did not change with the CCS payload", direction.name)
				}
				if direction.original.IV == direction.altered.IV {
					t.Errorf("%s IV did not change with the CCS payload", direction.name)
				}
			}
		})
	}
}

func TestTranscriptRejectsMissingRecordPayloads(t *testing.T) {
	for _, missing := range []struct {
		name string
		wire []byte
	}{
		{"nil", nil},
		{"short header", []byte{0x16, 0x03}},
		{"empty payload", []byte{0x16, 0x03, 0x03, 0, 0}},
	} {
		for i, name := range []string{"ClientHello", "ServerHello", "ChangeCipherSpec"} {
			t.Run(name+"/"+missing.name, func(t *testing.T) {
				records := [3][]byte{
					{0x16, 0x03, 0x01, 0, 4, 1, 0, 0, 0},
					{0x16, 0x03, 0x03, 0, 4, 2, 0, 0, 0},
					ChangeCipherSpec(),
				}
				records[i] = missing.wire
				transcript := Transcript(records[0], records[1], records[2])
				if _, err := DeriveSession(make([]byte, 32), make([]byte, 32), TLS_AES_128_GCM_SHA256, transcript); err == nil {
					t.Fatal("derived keys despite a missing opening record payload")
				}
			})
		}
	}
}
