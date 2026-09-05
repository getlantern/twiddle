// twiddle — interactive byte map of a real ClientHello.
// The data is a genuine Chrome 151 capture from the repository's test corpus.

const DATA = {"hex":"160301071e0100071a030332b9030aeffdef42a6aea90f5fe5746f2e96cac18d254cccc580cfec37d867592086f330bfeaf220b959b27c0476a840e89b07c3549eba1954e05292fdfcd8352800204a4a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006b1baba0000000a000c000a6a6a11ec001d0017001844cd0005000302683200120000002d00020101fe0d011a00000100011700207ffe9093dd9be9f6d1d244b9c333bf3ec44d367d8522e8fd920f454e04f3b43a00f0285d67cf7cbafb696accac747a6f2f6bd7d77271f1879df9c7e81d798fed1a269f4a367dd25a719c13d0ce6b2b80faf7ab84f82009e494da9fe247cec667e1e8825c0592fdd25a13719690289cb66375f90afa8a8eb192def623035b459c5b1b0d330160c20153d3dd721b7ab65da064a9301269e930199f00c87cd68cbb7d0b14d6cf06120d38de1723361060e13818e8196e7876e2b56b63780e1b9143070b4fca4660a42a605ea68df6ab892b1d281f5d88b8b5333e0f506eb6b1a379fe37d2527480e5195f32adef0f4fe8acf487b5ec2dcfb4bb37965643e1058c558bb01958cbafdef1bddb3734c342965fe7c5001b0003020002000b0002010000230000003304ef04ed6a6a00010011ec04c0712a5f8cf4b2d0f1028e5a608c374691c84d5939b2cffa0748e7407e971d141a567cf149a86b7d3366aecf4660e1c8717a779adcd5aa65141619328b851a23ba835b0c3b662c6aa467400345639741b5081f2aa9e719153492399476aa2b7431295c300ae00dfdebb5e13495758307e9a640002dbdce5214f3c62c2dab9f81e83c7d31c839191bb6a3c956013406821ddba61ac78a198bec113f505e45252ee0e35b33d88918d539090236b6508a7e49194d8a69d066244605c1f7417682e211f701a515a565819c41bc97b2b66643b18c0ada073a76144beb860a38006125f14dda31c931621a8e7375545093071a59b6ac624d65a73526c261bcafba9593553916e550ccafa8bc95955b234878b5e9a816f493efa6bd2be0a24ec576485617f7f91a1dc13761729b85c6af4950a7cc2aa9b8223ae7d33a3e287d305644e21083c69393ef371947b680dec35583fb120ae2436c9abbfbea3362b7b20c002bdf9556a65bab17ab7cda709437b37c1776c32d3517bce79c7af63aa6cbc8bae7a16c2721b036750553480c2b323073ba38ca6a893b93c7125b8a006fc2242a95b692b72733f479b2c4fac484d51d3ac275958b0e06a9b2f1dc64c2fb28efd8bd79d3bab3dac11d6b3698e40feee3997b99b235db1af7e878926424c24c6a29b9291fc0b9988870c7a2859de46824e78be1e683bb86b6fc97b9af2bb75a79091ab1b7dfc96eaee21da363af8867cdd25c85be89bc7f3658a040ce3c5b6db0cc1667932ed88976eca41f054197c85112097181f4a0676282914e377a02172f6659a5a833714a152096fa1bd8fc62ab8990b7e5309fdb68c7c497f1e36170d201f38aca4ee2303308c8a4f38f7f4114f1b5341ec0987ebb1e1d8a41045c9d80eb3c7f2a488f5bc2d8ec54f5187bd344992ebc09e0387757bba7497575fc45bdcd98b47ea1519717c89f89be551a43c2258c654b9b6ad80477c5b757f7a523d72a0f712d2f1a55d0a68f06602233b3cc2e7b2568f4b44f0c8494319bd1a82e4807aa45400624215786c0cb3cb92be1b22f42046cd8d1b646576a9f6997c5c794d5856f78e338da185cb9d5467e2256a73a4654ec19e2b686702c2287e1216580024ef1866c067d4c50289bbb65972783f4f52804f5148f00ca7a0682a0d8074a5989921479d4380b41db206fd9a9faa270a6e78b4716b1dfb174a811a63dc05615390980d1ad2b2977edb4bf664ca681f51553e98483b337478237bea2ae62f73ee9ba50b8821506cc7477d3c0fad9166852856cb8b9728aad1342052660ae6fc7c59d7b1ff178a1b21181b9b869ba8a68578b3c7e68cab4207da3489a28fb188d23b390f502f67284c7765e14570dc519234c003b5ef02005e3236e30a2e0764d34692b52ab6c7d0a8e15536a340cbfef67477bc30266987ba0938da4280aa6b67b369b5126d48618996c55808b6745069b595c3e38bd4752b3cf418ff120cbb9932e3b855f5309b2b7932abe46524e8b8dcf87242b90bbcc1a306d15673dc942373991c68a9369116b92a34203e682ea284a52520e01370bbd69a520a834e7e69f740b977752b5670412a2e08060166a33b7be36bb1f79511cdc89551cc27ed962bb0dc1ea94ed9b06ede14a8a854af1fe10d28f20a433f32ef4b39342389ec569eb2adace45a1c0d3f8934665349bf40d719531a90493c55451198a22740bf9a762001d00206ea57e8b55a852914213ab66201ee4a90ecbc860b052a6bef51661e1401d9b46000500050100000000002b0007061a1a03040303000d00180016090409050906040308040401050308050501080606010017000012e000021f40ff010001000000000e000c0000096c6f63616c686f73740010000e000c02683208687474702f312e312a2a000100","total":1827,"spans":[{"off":0,"len":5,"name":"record header","kind":"frame","note":"TLS record: type 0x16 (handshake), legacy version, length. Rewritten because our edits change the length."},{"off":5,"len":4,"name":"handshake header","kind":"frame","note":"ClientHello (0x01) plus a 3-byte length. Rewritten for the same reason."},{"off":9,"len":2,"name":"legacy_version","kind":"keep","note":"Frozen at 0x0303 since TLS 1.3. The real version lives in supported_versions."},{"off":11,"len":32,"name":"random","kind":"twiddle","note":"32 bytes of client entropy. Re-randomised every connection \u2014 replaying a captured value would repeat one browser's nonce."},{"off":43,"len":33,"name":"legacy_session_id","kind":"twiddle","note":"Chrome sends 32 random bytes on every hello we captured. Re-randomised. The server must echo it, so anything placed here appears twice on the wire."},{"off":76,"len":34,"name":"cipher_suites","kind":"keep","note":"Copied verbatim. Chrome's list and order are part of its fingerprint; changing either is a tell."},{"off":110,"len":2,"name":"compression_methods","kind":"keep","note":"Always the single null method in TLS 1.3."},{"off":112,"len":2,"name":"extensions length","kind":"frame","note":"Recomputed after every edit \u2014 one of five nested lengths that cascade."},{"off":114,"len":4,"name":"GREASE","kind":"keep","note":"RFC 8701 placeholder. Chrome pins one at each end of the extension list; we keep them pinned there while shuffling everything between."},{"off":118,"len":16,"name":"supported_groups","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":134,"len":9,"name":"application_settings","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":143,"len":4,"name":"signed_certificate_timestamp","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":147,"len":6,"name":"psk_key_exchange_modes","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":153,"len":286,"name":"encrypted_client_hello","kind":"twiddle","note":"GREASE ECH. Re-randomised and resized to one of the buckets measured off real Chrome \u2014 186, 218, 250 or 282 bytes, varying per connection independently of SNI length."},{"off":439,"len":7,"name":"compress_certificate","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":446,"len":6,"name":"ec_point_formats","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":452,"len":4,"name":"session_ticket","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":456,"len":1267,"name":"key_share","kind":"twiddle","note":"Fresh X25519 and ML-KEM-768 keys every connection. They must be VALID: filling them with random bytes made real servers reply illegal_parameter, which would have given a censor a replay distinguisher."},{"off":1723,"len":9,"name":"status_request","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":1732,"len":11,"name":"supported_versions","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":1743,"len":28,"name":"signature_algorithms","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":1771,"len":4,"name":"extended_master_secret","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":1775,"len":6,"name":"server_padding","kind":"keep","note":"BoringSSL's 0x12e0, field-trial gated. Present only on established Chrome profiles, and asking for 8000 bytes of server padding obliges the reply to carry it \u2014 so we never depend on it."},{"off":1781,"len":5,"name":"renegotiation_info","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":1786,"len":18,"name":"server_name","kind":"twiddle","note":"Rewritten to the cover domain this egress masquerades as. The only field whose length we change on purpose; the delta cascades through five nested length fields."},{"off":1804,"len":18,"name":"ALPN","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":1822,"len":5,"name":"GREASE","kind":"keep","note":"RFC 8701 placeholder. Chrome pins one at each end of the extension list; we keep them pinned there while shuffling everything between."}],"extCount":19};

const REWRITES = {
  "record header": ["frame", "One handshake record (0x16), record version 0x0301, and a recomputed record length. The separate ClientHello legacy_version is preserved."],
  "random": ["twiddle", "Resumption: fresh 32 random bytes. Full handshake: a domain-separated HMAC-SHA256 over the entire final hello, calculated with this field zeroed, then written here."],
  "legacy_session_id": ["twiddle", "Fresh random contents, preserving the template's length (32 bytes here). The server echoes this value."],
  "cipher_suites": ["twiddle", "Only GREASE identifiers are redrawn. Ordinary cipher-suite IDs, list length, and order are preserved; highlighting covers the whole field, not just changed bytes."],
  "GREASE": ["twiddle", "The extension type is redrawn from the 16 GREASE values. First and last GREASE types must differ; their positions stay pinned around the shuffled interior. Extension payloads are preserved."],
  "supported_groups": ["twiddle", "Redraw GREASE identifiers to match the GREASE key-share group. Ordinary group IDs and list order are unchanged."],
  "supported_versions": ["twiddle", "Redraw GREASE version identifiers; preserve actual version IDs and their order."],
  "signature_algorithms": ["keep", "This captured list has no GREASE and is copied. When a template does contain GREASE signature IDs, Twiddle redraws those IDs while preserving ordinary IDs and order."],
  "encrypted_client_hello": ["twiddle", "Outer GREASE ECH: fresh config_id, 32-byte enc, and payload of 144/176/208/240 bytes, chosen uniformly. Preserve HPKE KDF/AEAD IDs. Full mode replaces the payload's first 144 bytes with its companion ticket; the remainder is random padding. No ECH extension is added if absent."],
  "key_share": ["twiddle", "Fresh valid standalone X25519 and, if offered, ML-KEM-768 plus X25519 hybrid public values. Only standalone X25519 supplies the tunnel's real key agreement; no post-quantum forward secrecy. GREASE contents stay zero; unrecognized groups are also zeroed."],
  "session_ticket": ["keep", "Already empty in this capture. Template import sanitization empties any captured legacy ticket payload; per-connection emission leaves the empty extension intact."],
  "server_padding": ["keep", "Historical BoringSSL extension 0x12e0, copied if present. Twiddle does not add it when absent. Chrome 152 measurements omit it; preserving a request does not by itself establish reply fidelity."],
  "server_name": ["twiddle", "Replace with the configured cover hostname when supplied, and recompute nested lengths. No compensating padding preserves the old size; ECH resizing and authentication also change the final message length."]
};
DATA.spans.forEach(span => {
  const rewrite = REWRITES[span.name];
  if (rewrite) [span.kind, span.note] = rewrite;
});

// The captured hello has no PSK; only the resumption-shaped output adds one.
const APPENDED = {
  name: "pre_shared_key",
  kind: "add",
  note: "Resumption only: replace any existing PSK extension with the supplied credential ticket, a fresh random four-byte obfuscated_ticket_age, and a newly computed 32- or 48-byte Twiddle HMAC binder. Place last, after trailing GREASE. Full-handshake mode removes this extension and authenticates through ECH and random instead."
};

const COPY = "Copied unchanged.";
const SAME_LENGTH = "Serialized again; same value for this sample.";
const SAMPLE_PARTS = {
  0: [[1, "content_type", "Handshake (0x16).", "Emitted as 0x16."], [2, "record version", "0x0301, separate from ClientHello.legacy_version.", "Emitted as 0x0301."], [2, "record length", "1822 bytes after the record header.", "Recomputed: total emitted bytes minus 5."]],
  5: [[1, "handshake type", "ClientHello (0x01).", "Emitted as 0x01."], [3, "handshake body length", "1818 bytes.", "Recomputed: total emitted bytes minus 9."]],
  9: [[2, "legacy_version", "0x0303 (TLS 1.2 legacy marker).", COPY]],
  11: [[32, "random", "Captured client random, displayed verbatim here.", "Sanitize zeros it. Resumption replaces it with 32 fresh random bytes. Full mode finally overwrites it with the whole-hello HMAC-SHA256, calculated with this field zeroed."]],
  43: [[1, "session ID length", "32 bytes.", SAME_LENGTH], [32, "session ID", "Captured compatibility session ID.", "Sanitize zeros it; emission fills all 32 bytes with fresh randomness. The server echoes the new value."]],
  76: [[2, "cipher-suite vector length", "32 bytes / 16 entries.", SAME_LENGTH], [2, "GREASE cipher", "0x4a4a.", "Replace with the cipher GREASE draw."], ...Array.from({length: 15}, (_, i) => [2, `cipher suite ${i + 2}`, "Ordinary cipher-suite ID; order shown is the advertised preference order.", COPY])],
  110: [[1, "compression vector length", "One method.", SAME_LENGTH], [1, "compression method", "0x00 (null compression).", COPY]],
  112: [[2, "extension vector length", "1713 bytes / 19 extensions.", "Recomputed from all serialized extensions; grows further when resumption appends PSK."]],
  114: [],
  118: [[2, "group vector length", "10 bytes / five IDs.", COPY], [2, "GREASE group", "0x6a6a.", "Replace with the group GREASE draw; use that same draw in key_share."], [2, "group: X25519MLKEM768", "0x11ec.", COPY], [2, "group: X25519", "0x001d.", COPY], [2, "group: secp256r1", "0x0017.", COPY], [2, "group: secp384r1", "0x0018.", COPY]],
  134: [[2, "ALPS protocol-list length", "3 bytes.", COPY], [1, "protocol-name length", "2 bytes.", COPY], [2, "ALPS protocol name", "ASCII h2. This is application_settings (0x44cd), not the separate ALPN extension.", "Copied as an opaque payload; Twiddle does not negotiate ALPS settings."]],
  143: [],
  147: [[1, "PSK mode vector length", "One mode.", COPY], [1, "PSK mode", "0x01 (psk_dhe_ke).", "Preserved even in the full-shaped opening; advertising a mode does not require offering a PSK."]],
  153: [[1, "ECH ClientHello type", "0x00 (outer).", "Re-emitted as outer ECH."], [2, "HPKE KDF ID", "0x0001 (HKDF-SHA256).", COPY], [2, "HPKE AEAD ID", "0x0001 (AES-128-GCM).", COPY], [1, "config_id", "Captured 0x17.", "Fresh random byte."], [2, "enc length", "32 bytes.", "Rebuilt as 32."], [32, "enc", "Captured encapsulated-key-shaped bytes.", "Replace with 32 random bytes; no real ECH encryption is performed."], [2, "payload length", "240 bytes.", "Rebuilt from a uniform choice of 144, 176, 208, or 240."], [240, "payload", "Captured opaque ECH payload.", "Resumption: entirely fresh random bytes. Full: first 144 bytes are the supplied companion ticket; remaining bytes are fresh random padding. The original 240 bytes are not replayed."]],
  439: [[1, "compression-algorithm vector length", "2 bytes.", COPY], [2, "certificate compression algorithm", "0x0002 (Brotli).", "Copied; advertising certificate compression does not make Twiddle implement it."]],
  446: [[1, "point-format vector length", "One format.", COPY], [1, "EC point format", "0x00 (uncompressed).", COPY]],
  452: [],
  456: [[2, "key-share vector length", "1261 bytes, three entries.", COPY], [2, "GREASE key-share group", "0x6a6a.", "Replace with the same GREASE draw as supported_groups."], [2, "GREASE key length", "One byte.", COPY], [1, "GREASE key contents", "0x00.", "Zeroed, so this captured value remains 00."], [2, "hybrid group", "0x11ec (X25519MLKEM768).", COPY], [2, "hybrid key length", "1216 bytes.", COPY], [1184, "ML-KEM-768 encapsulation key", "First part of the hybrid public share.", "Generate a fresh valid ML-KEM-768 key, copy its encapsulation key, discard the private key."], [32, "hybrid X25519 public key", "Second part of the hybrid public share.", "Generate a fresh valid X25519 public key and discard its private key; this is not the tunnel's key agreement."], [2, "standalone group", "0x001d (X25519).", COPY], [2, "standalone key length", "32 bytes.", COPY], [32, "standalone X25519 public key", "Captured public key.", "Rerandomize first refreshes it; SetKeyShare replaces it again and retains that final private key for the actual tunnel key agreement."]],
  1723: [[1, "certificate status type", "0x01 (OCSP).", COPY], [2, "responder-ID list length", "Zero; no responder IDs follow.", COPY], [2, "request-extensions length", "Zero; no OCSP request extensions follow.", COPY]],
  1732: [[1, "version vector length", "6 bytes / three IDs.", COPY], [2, "GREASE version", "0x1a1a.", "Replace with the independent version GREASE draw."], [2, "supported version", "0x0304 (TLS 1.3).", COPY], [2, "supported version", "0x0303 (TLS 1.2).", COPY]],
  1743: [[2, "signature vector length", "22 bytes / eleven IDs.", COPY], ...["mldsa44", "mldsa65", "mldsa87", "ecdsa_secp256r1_sha256", "rsa_pss_rsae_sha256", "rsa_pkcs1_sha256", "ecdsa_secp384r1_sha384", "rsa_pss_rsae_sha384", "rsa_pkcs1_sha384", "rsa_pss_rsae_sha512", "rsa_pkcs1_sha512"].map(name => [2, "signature scheme", name + ". No GREASE in this sample.", COPY])],
  1771: [],
  1775: [[2, "server-padding request", "0x1f40 = 8000 bytes, historical 0x12e0 extension.", "Copied as opaque bytes, not removed or recalculated. Preserving this request does not prove the synthesized reply satisfies it."]],
  1781: [[1, "renegotiated_connection length", "Zero; the renegotiated_connection vector is empty.", COPY]],
  1786: [[2, "server-name list length", "12 bytes.", "Rebuilt as N + 3 for an N-byte configured cover name."], [1, "server-name type", "0x00 (host_name).", "SetSNI re-emits 0x00."], [2, "hostname length", "9 bytes.", "Rebuilt as N."], [9, "hostname", "ASCII localhost.", "Sanitize writes nine x characters. SetSNI replaces them with the configured cover hostname; a raw Twiddle call with empty CoverSNI leaves the input SNI unchanged."]],
  1804: [[2, "ALPN list length", "12 bytes.", COPY], [1, "first protocol length", "2 bytes.", COPY], [2, "first protocol", "ASCII h2.", COPY], [1, "second protocol length", "8 bytes.", COPY], [8, "second protocol", "ASCII http/1.1.", "Copied; the advertised ALPN list is not a promise that the tunnel carries HTTP."]],
  1822: [[1, "trailing GREASE payload", "0x00.", "Copied, not rerandomized. This is separate from the zeroed GREASE key-share byte."]]
};

const FIELD_PURPOSE = {
  "record header": "Frames a TLS record on the byte stream: identifies its content type and tells the receiver how many bytes to read. A record is a container, distinct from the handshake message inside it.",
  "handshake header": "Identifies this handshake message as a ClientHello and gives its body length. The ClientHello opens negotiation by advertising the client's capabilities.",
  "legacy_version": "A compatibility marker for older TLS parsers. In TLS 1.3 it remains 0x0303; supported_versions carries the actual version offer.",
  "random": "Fresh client randomness distinguishes handshakes. In real TLS 1.3 it is covered by the handshake transcript, binding the exchange to this opening; it is not a secret or a public key.",
  "legacy_session_id": "Originally identified sessions for older TLS resumption. TLS 1.3 compatibility mode uses a nonempty value, echoed by the server, to look familiar to middleboxes; TLS 1.3 resumption itself uses pre_shared_key.",
  "cipher_suites": "Lists cryptographic suites the client supports. TLS 1.3 suites select authenticated encryption and a key-schedule hash; older suites also encode key-exchange and authentication choices. GREASE entries are placeholders, not usable suites.",
  "compression_methods": "The legacy TLS record-compression offer. TLS 1.3 permits only null compression; this is separate from certificate compression below.",
  "extensions length": "Delimits the entire extension block. Each extension then has its own type and length, allowing a parser to skip extensions it does not understand.",
  "GREASE": "Generate Random Extensions And Sustain Extensibility: deliberately advertise reserved, unsupported values so servers and middleboxes keep tolerating unfamiliar values. This prevents implementations from accepting only today's known choices. GREASE is not an encryption algorithm, secret channel, or padding scheme; its values must not be negotiated as real features.",
  "supported_groups": "Advertises supported key-exchange groups, such as X25519, elliptic curves, or a hybrid post-quantum group. This is the capability list; key_share supplies actual public values for some of those groups.",
  "application_settings": "Application-Layer Protocol Settings (ALPS) allows application settings to be exchanged during the TLS handshake for a selected application protocol. This offer names h2; it is distinct from ALPN, which selects the protocol itself.",
  "signed_certificate_timestamp": "Requests Certificate Transparency evidence from the server: signed promises by logs to record its certificate. The empty ClientHello extension is a request, not a missing timestamp payload.",
  "psk_key_exchange_modes": "Says how the client can use a pre-shared key: alone or combined with fresh Diffie–Hellman key exchange. This sample offers psk_dhe_ke, which combines PSK authentication with fresh key agreement.",
  "encrypted_client_hello": "Real Encrypted ClientHello (ECH) encrypts an inner ClientHello to protect sensitive fields such as the true server name, while leaving an outer hello visible. This sample uses GREASE ECH: a plausible dummy offer, not an encrypted inner hello. Twiddle rebuilds that dummy body and optionally uses it to carry its own ticket.",
  "compress_certificate": "Advertises algorithms the client can use to decompress the server's certificate message, reducing handshake bandwidth. This sample offers Brotli. It does not enable compression of application data.",
  "ec_point_formats": "A legacy elliptic-curve capability indicating how curve points may be encoded. It matters to older EC TLS handshakes; TLS 1.3 key-share encodings are defined by their groups instead.",
  "session_ticket": "The legacy session-ticket resumption mechanism. An empty offer signals ticket support without presenting an existing ticket. TLS 1.3 uses pre_shared_key instead; this is not Twiddle's authentication-ticket carrier.",
  "key_share": "Carries public key-exchange material so a server can establish a shared secret without first requesting a key. The sample includes a GREASE placeholder, a hybrid X25519/ML-KEM share, and standalone X25519. Twiddle uses only the final standalone X25519 private key for its actual agreement.",
  "status_request": "Requests certificate-status stapling: the server can send an OCSP response about certificate revocation with its handshake, avoiding a separate client query to the certificate authority.",
  "supported_versions": "Advertises the TLS versions the client actually supports. This supersedes legacy_version for TLS 1.3 negotiation; the GREASE entry tests tolerance of unknown version IDs.",
  "signature_algorithms": "Advertises signature schemes the client can verify, constraining server authentication choices in a real TLS handshake. These are signature capabilities, not key-exchange groups or record-encryption ciphers.",
  "extended_master_secret": "An older-TLS security extension that binds the master secret to the handshake transcript, preventing session-splicing attacks. TLS 1.3 builds transcript binding into its key schedule and does not negotiate this extension.",
  "server_padding": "A historical BoringSSL extension requesting extra server-side handshake padding to alter observable response sizes. It is not client-side padding and does not absorb changes to the ClientHello's length.",
  "renegotiation_info": "Signals secure renegotiation support in older TLS and binds later renegotiations to the existing connection. Its empty vector is normal for the initial handshake. TLS 1.3 does not support renegotiation.",
  "server_name": "Server Name Indication (SNI) tells the server which hostname the client wants, allowing multiple sites and certificates to share an IP address. Ordinary plaintext SNI is visible to observers; Twiddle supplies its cover hostname here.",
  "ALPN": "Application-Layer Protocol Negotiation advertises protocols the client can speak over TLS so the server can select one, such as HTTP/2 (h2) or HTTP/1.1. It selects an application protocol, not a cipher suite."
};

const sampleFields = document.getElementById("sample-fields");
DATA.spans.forEach(span => {
  const parts = SAMPLE_PARTS[span.off].map(part => [...part]);
  const extension = span.off >= 114;
  const type = DATA.hex.slice(span.off * 2, span.off * 2 + 4);
  if (extension) {
    parts.unshift(
      [2, "extension type", "0x" + type + ".", span.name === "GREASE" ? "Redraw this GREASE extension type; leading and trailing types must differ." : SAME_LENGTH],
      [2, "extension body length", `${span.len - 4} bytes, excluding this four-byte header.`, "Recomputed from the output body. " + ([153, 1786].includes(span.off) ? "Can change when the body is rebuilt." : "Same value for this sample.")]
    );
  }
  const details = document.createElement("details");
  details.id = "sample-field-" + span.off;
  details.className = "sample-field";
  const summary = document.createElement("summary");
  summary.textContent = `${span.off}–${span.off + span.len - 1} · ${span.name}${extension ? " · 0x" + type : ""} · ${span.len} B`;
  details.appendChild(summary);
  const purpose = document.createElement("p");
  purpose.className = "field-purpose";
  if (!FIELD_PURPOSE[span.name]) throw new Error("Missing field purpose: " + span.name);
  purpose.textContent = "What it does: " + FIELD_PURPOSE[span.name];
  details.appendChild(purpose);
  const note = document.createElement("p");
  note.textContent = "In Twiddle: " + span.note;
  if (extension) note.textContent += span.off === 114 ? " Remains first." : span.off === 1822 ? " Remains last among these 19; PSK follows it on resumption." : " This interior extension moves when shuffled.";
  if (extension && span.len === 4) note.textContent += " Empty body: there are no nested payload fields.";
  details.appendChild(note);
  const table = document.createElement("table");
  const head = document.createElement("tr");
  for (const label of ["Original offset / field", "Captured bytes & meaning", "Twiddle treatment"]) {
    const th = document.createElement("th"); th.scope = "col"; th.textContent = label; head.appendChild(th);
  }
  table.appendChild(head);
  let offset = span.off;
  for (const [length, name, meaning, treatment] of parts) {
    const row = document.createElement("tr");
    row.dataset.offset = offset; row.dataset.length = length;
    const field = document.createElement("td");
    field.textContent = `${offset}–${offset + length - 1} · ${name}`;
    const value = document.createElement("td");
    const hex = document.createElement("code");
    hex.textContent = DATA.hex.slice(offset * 2, (offset + length) * 2).match(/../g).join(" ");
    if (length > 32) {
      const raw = document.createElement("details");
      const label = document.createElement("summary"); label.textContent = `Show all ${length} captured bytes`;
      raw.appendChild(label); raw.appendChild(hex); value.appendChild(raw);
    } else value.appendChild(hex);
    const decoded = document.createElement("p"); decoded.textContent = meaning; value.appendChild(decoded);
    const action = document.createElement("td"); action.textContent = treatment;
    row.appendChild(field); row.appendChild(value); row.appendChild(action); table.appendChild(row);
    offset += length;
  }
  if (offset !== span.off + span.len) throw new Error("Incomplete sample breakdown: " + span.name);
  details.appendChild(table); sampleFields.appendChild(details);
});
const sampleExpand = document.getElementById("sample-expand");
sampleExpand.addEventListener("click", () => {
  const expand = Array.from(sampleFields.children).some(field => !field.open);
  for (const field of sampleFields.children) field.open = expand;
  sampleExpand.textContent = expand ? "Collapse all fields" : "Expand all fields";
  sampleExpand.setAttribute("aria-expanded", String(expand));
});

const grid   = document.getElementById("grid");
const fields = document.getElementById("fields");
const ptag   = document.getElementById("ptag");
const pname  = document.getElementById("pname");
const pwhere = document.getElementById("pwhere");
const pnote  = document.getElementById("pnote");
document.getElementById("total").textContent = DATA.total.toLocaleString() + " bytes";

// byte -> span index, so hovering any byte finds its field in O(1)
const owner = new Int16Array(DATA.total).fill(-1);
DATA.spans.forEach((s, i) => {
  for (let k = s.off; k < s.off + s.len && k < DATA.total; k++) owner[k] = i;
});

const frag = document.createDocumentFragment();
for (let i = 0; i < DATA.total; i++) {
  const b = document.createElement("b");
  b.textContent = DATA.hex.substr(i * 2, 2) + " ";
  b.dataset.i = i;
  const s = DATA.spans[owner[i]];
  if (s) b.className = "k-" + s.kind;
  frag.appendChild(b);
}
grid.appendChild(frag);
const cells = grid.children;

DATA.spans.forEach((s, i) => {
  const li = document.createElement("li");
  li.textContent = s.name;
  li.dataset.s = i;
  if (s.kind === "twiddle" || s.kind === "add") li.className = "t";
  fields.appendChild(li);
});
const extra = document.createElement("li");
extra.textContent = APPENDED.name + "  (resumption only)";
extra.className = "t";
extra.dataset.s = "add";
fields.appendChild(extra);

let active = -1;
function show(idx) {
  if (idx === active) return;
  active = idx;
  for (const li of fields.children) li.classList.remove("active");

  if (idx === "add") {
    for (let i = 0; i < cells.length; i++) { cells[i].classList.remove("on"); cells[i].classList.add("dimmed"); }
    paint(APPENDED, "resumption: appended after the trailing GREASE", "add");
    extra.classList.add("active");
    return;
  }
  const s = DATA.spans[idx];
  if (!s) return;
  for (let i = 0; i < cells.length; i++) {
    const within = i >= s.off && i < s.off + s.len;
    cells[i].classList.toggle("on", within);
    cells[i].classList.toggle("dimmed", !within);
  }
  paint(s, `offset ${s.off} · ${s.len} byte${s.len === 1 ? "" : "s"}`, s.kind);
  const li = fields.querySelector(`[data-s="${idx}"]`);
  if (li) li.classList.add("active");

  // Bring the highlighted run into view. Selecting a field near the end of a
  // 1827-byte record would otherwise highlight bytes scrolled out of the grid.
  const first = cells[s.off];
  if (first) {
    const gTop = grid.getBoundingClientRect().top;
    const bTop = first.getBoundingClientRect().top;
    const target = grid.scrollTop + (bTop - gTop) - grid.clientHeight / 3;
    if (Math.abs(target - grid.scrollTop) > 12) {
      grid.scrollTo({ top: Math.max(0, target), behavior: "smooth" });
    }
  }
}

const LABEL = { twiddle: "twiddled", keep: "copied verbatim", frame: "length, recomputed", add: "appended by us" };
function paint(s, where, kind) {
  ptag.className = "tag " + kind;
  ptag.textContent = LABEL[kind] || kind;
  pname.textContent = s.name;
  pwhere.textContent = where;
  pnote.textContent = s.note;
}

function clear() {
  active = -1;
  for (let i = 0; i < cells.length; i++) cells[i].classList.remove("on", "dimmed");
  for (const li of fields.children) li.classList.remove("active");
  ptag.className = "tag keep";
  ptag.textContent = "hover a byte";
  pname.textContent = "The whole record";
  pwhere.textContent = DATA.total + " bytes · " + DATA.extCount + " extensions";
  pnote.textContent = "These are original captured bytes. Twiddle shuffles interior extensions and rewrites selected fields; a highlighted field can contain unchanged bytes too. Resumption appends pre_shared_key; full-handshake mode uses ECH and random instead.";
}

grid.addEventListener("mouseover", e => {
  if (e.target.tagName === "B") show(owner[+e.target.dataset.i]);
});
fields.addEventListener("mouseover", e => {
  if (e.target.tagName === "LI") {
    const v = e.target.dataset.s;
    show(v === "add" ? "add" : +v);
  }
});
grid.addEventListener("mouseleave", clear);
fields.addEventListener("mouseleave", clear);
clear();

// staggered entrance, motion-preference respecting
if (!matchMedia("(prefers-reduced-motion: reduce)").matches) {
  document.querySelectorAll(".rise").forEach((el, i) => {
    el.style.animationDelay = (i * 110) + "ms";
  });
}
