package twiddle

// testTranscript is a fixed stand-in for the opening, for tests that only need
// two Sessions whose keys agree. DeriveSession refuses an empty transcript, so
// there is no unbound derivation anywhere -- including in tests, where one
// would quietly become the example everyone copies.
func testTranscript() []byte { return []byte("twiddle test transcript") }
