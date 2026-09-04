// twiddlecred mints a server ticket key and a client credential, for
// provisioning and for tests. The server holds the key; the client holds only
// the credential it was issued.
package main

import (
	"encoding/base64"
	"encoding/hex"
	"flag"
	"fmt"

	"github.com/getlantern/twiddle"
)

func main() {
	clientID := flag.Uint64("client-id", 1, "client identifier embedded in the ticket")
	cover := flag.String("cover", "", "measured cover host (required)")
	printPool := flag.Bool("print-pool", false, "write a usable hello pool to stdout (embedded snapshot; tests only)")
	flag.Parse()

	if *printPool {
		p, err := twiddle.LoadPool(twiddle.Sources{AllowEmbedded: true})
		if err != nil {
			panic(err)
		}
		fmt.Print(twiddle.FormatPool(p.Hellos))
		return
	}

	if *cover == "" {
		panic("twiddlecred: -cover is required")
	}
	profile, err := twiddle.CoverFor(*cover)
	if err != nil {
		panic(err)
	}
	k, err := twiddle.NewTicketKey()
	if err != nil {
		panic(err)
	}
	cred, err := k.Issue(*clientID, profile.TicketLen)
	if err != nil {
		panic(err)
	}
	fmt.Printf("ticket_key=%s\n", hex.EncodeToString(k[:]))
	fmt.Printf("ticket=%s\n", base64.StdEncoding.EncodeToString(cred.Ticket))
	// The full-handshake companion. Provisioning that omits it leaves the
	// client resumption-only, which is the distinguisher the carrier exists to
	// remove -- see docs/full-handshake-carrier.md.
	fmt.Printf("full_ticket=%s\n", base64.StdEncoding.EncodeToString(cred.FullTicket))
	fmt.Printf("psk=%s\n", hex.EncodeToString(cred.PSK[:]))
}
