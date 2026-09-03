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
	ticketLen := flag.Int("ticket-len", twiddle.DefaultTicketLen, "ticket length; should match the cover identity's real server")
	cover := flag.String("cover", "", "cover host; sets ticket-len from measured values when given")
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

	if *cover != "" {
		profile, err := twiddle.CoverFor(*cover)
		if err != nil {
			panic(err)
		}
		*ticketLen = profile.TicketLen
	}
	k, err := twiddle.NewTicketKey()
	if err != nil {
		panic(err)
	}
	cred, err := k.Issue(*clientID, *ticketLen)
	if err != nil {
		panic(err)
	}
	fmt.Printf("ticket_key=%s\n", hex.EncodeToString(k[:]))
	fmt.Printf("ticket=%s\n", base64.StdEncoding.EncodeToString(cred.Ticket))
	fmt.Printf("psk=%s\n", hex.EncodeToString(cred.PSK[:]))
}
