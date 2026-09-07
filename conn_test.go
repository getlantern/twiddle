package twiddle

import "testing"

// testTranscript is a fixed stand-in for the opening, for tests that only need
// two Sessions whose keys agree. DeriveSession refuses an empty transcript, so
// there is no unbound derivation anywhere -- including in tests, where one
// would quietly become the example everyone copies.
func testTranscript() []byte { return []byte("twiddle test transcript") }

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
