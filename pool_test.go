package twiddle

import "testing"

func TestDefaultPoolIsUsable(t *testing.T) {
	p := DefaultPool()
	if len(p) < 4 {
		t.Fatalf("embedded pool has only %d hellos", len(p))
	}
	k := ticketKey(t)
	cred, _ := k.Issue(1, DefaultTicketLen)
	for i, rec := range p {
		h, err := ParseClientHello(rec)
		if err != nil {
			t.Fatalf("pool[%d]: %v", i, err)
		}
		if h.Find(ExtPreSharedKey) != nil {
			t.Errorf("pool[%d] is a resumption hello; the pool should hold full hellos", i)
		}
		wire, _, err := Twiddle(rec, Options{CoverSNI: "www.microsoft.com", Credential: cred, BinderLen: 32})
		if err != nil {
			t.Fatalf("pool[%d]: %v", i, err)
		}
		back, err := ParseClientHello(wire)
		if err != nil {
			t.Fatalf("pool[%d]: %v", i, err)
		}
		if _, err := VerifyTicketAuth(back, k, 0); err != nil {
			t.Fatalf("pool[%d]: %v", i, err)
		}
	}
	t.Logf("embedded pool: %d hellos, all twiddle and verify", len(p))
}
