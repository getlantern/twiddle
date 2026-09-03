package twiddle

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The transport ships without a TLS library, and that is load-bearing rather
// than decorative: it is why twiddle is free of the preset-staleness treadmill
// uTLS lives on, and why its fidelity comes from harvested bytes instead of
// from a stack someone has to keep matching Chrome.
//
// A property defended only by remembering is not defended. Measuring a cover
// genuinely needs a TLS stack, so the dependency exists in this repo -- under
// harvest/, with the rest of the tooling, where it cannot reach a shipped
// binary. This test is what keeps it there: it fails the moment any package a
// consumer could import acquires one.
//
// Anything that already links a TLS stack can still probe with its own and feed
// the result through CoverProfile.Adopt, which needs none.
func TestShippedPackagesImportNoTLSLibrary(t *testing.T) {
	// Import paths that mean "a TLS implementation", as opposed to the
	// primitives twiddle legitimately uses (crypto/ecdh, crypto/mlkem, and the
	// AEADs behind its own record layer).
	banned := []string{
		"crypto/tls",
		"github.com/refraction-networking/utls",
		"github.com/sagernet/sing-box",
	}

	var offenders []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			// harvest/ is measurement tooling and is allowed a TLS stack;
			// nothing there is linked into a shipped binary.
			if info.Name() == "harvest" || info.Name() == "site" ||
				strings.HasPrefix(info.Name(), ".") && info.Name() != "." {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if perr != nil {
			return perr
		}
		for _, imp := range f.Imports {
			got := strings.Trim(imp.Path.Value, `"`)
			for _, b := range banned {
				if got == b || strings.HasPrefix(got, b+"/") {
					offenders = append(offenders, path+" imports "+got)
				}
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, o := range offenders {
		t.Errorf("a shipped package pulled in a TLS library: %s", o)
	}
	if len(offenders) > 0 {
		t.Log("if this is a measurement tool, it belongs under harvest/; if it is runtime " +
			"probing, the caller should probe with its own stack and use CoverProfile.Adopt")
	}
}
