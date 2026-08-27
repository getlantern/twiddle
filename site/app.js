// twiddle — interactive byte map of a real ClientHello.
// The data is a genuine Chrome 151 capture from the repository's test corpus.

const DATA = {"hex":"160301071e0100071a030332b9030aeffdef42a6aea90f5fe5746f2e96cac18d254cccc580cfec37d867592086f330bfeaf220b959b27c0476a840e89b07c3549eba1954e05292fdfcd8352800204a4a130113021303c02bc02fc02cc030cca9cca8c013c014009c009d002f0035010006b1baba0000000a000c000a6a6a11ec001d0017001844cd0005000302683200120000002d00020101fe0d011a00000100011700207ffe9093dd9be9f6d1d244b9c333bf3ec44d367d8522e8fd920f454e04f3b43a00f0285d67cf7cbafb696accac747a6f2f6bd7d77271f1879df9c7e81d798fed1a269f4a367dd25a719c13d0ce6b2b80faf7ab84f82009e494da9fe247cec667e1e8825c0592fdd25a13719690289cb66375f90afa8a8eb192def623035b459c5b1b0d330160c20153d3dd721b7ab65da064a9301269e930199f00c87cd68cbb7d0b14d6cf06120d38de1723361060e13818e8196e7876e2b56b63780e1b9143070b4fca4660a42a605ea68df6ab892b1d281f5d88b8b5333e0f506eb6b1a379fe37d2527480e5195f32adef0f4fe8acf487b5ec2dcfb4bb37965643e1058c558bb01958cbafdef1bddb3734c342965fe7c5001b0003020002000b0002010000230000003304ef04ed6a6a00010011ec04c0712a5f8cf4b2d0f1028e5a608c374691c84d5939b2cffa0748e7407e971d141a567cf149a86b7d3366aecf4660e1c8717a779adcd5aa65141619328b851a23ba835b0c3b662c6aa467400345639741b5081f2aa9e719153492399476aa2b7431295c300ae00dfdebb5e13495758307e9a640002dbdce5214f3c62c2dab9f81e83c7d31c839191bb6a3c956013406821ddba61ac78a198bec113f505e45252ee0e35b33d88918d539090236b6508a7e49194d8a69d066244605c1f7417682e211f701a515a565819c41bc97b2b66643b18c0ada073a76144beb860a38006125f14dda31c931621a8e7375545093071a59b6ac624d65a73526c261bcafba9593553916e550ccafa8bc95955b234878b5e9a816f493efa6bd2be0a24ec576485617f7f91a1dc13761729b85c6af4950a7cc2aa9b8223ae7d33a3e287d305644e21083c69393ef371947b680dec35583fb120ae2436c9abbfbea3362b7b20c002bdf9556a65bab17ab7cda709437b37c1776c32d3517bce79c7af63aa6cbc8bae7a16c2721b036750553480c2b323073ba38ca6a893b93c7125b8a006fc2242a95b692b72733f479b2c4fac484d51d3ac275958b0e06a9b2f1dc64c2fb28efd8bd79d3bab3dac11d6b3698e40feee3997b99b235db1af7e878926424c24c6a29b9291fc0b9988870c7a2859de46824e78be1e683bb86b6fc97b9af2bb75a79091ab1b7dfc96eaee21da363af8867cdd25c85be89bc7f3658a040ce3c5b6db0cc1667932ed88976eca41f054197c85112097181f4a0676282914e377a02172f6659a5a833714a152096fa1bd8fc62ab8990b7e5309fdb68c7c497f1e36170d201f38aca4ee2303308c8a4f38f7f4114f1b5341ec0987ebb1e1d8a41045c9d80eb3c7f2a488f5bc2d8ec54f5187bd344992ebc09e0387757bba7497575fc45bdcd98b47ea1519717c89f89be551a43c2258c654b9b6ad80477c5b757f7a523d72a0f712d2f1a55d0a68f06602233b3cc2e7b2568f4b44f0c8494319bd1a82e4807aa45400624215786c0cb3cb92be1b22f42046cd8d1b646576a9f6997c5c794d5856f78e338da185cb9d5467e2256a73a4654ec19e2b686702c2287e1216580024ef1866c067d4c50289bbb65972783f4f52804f5148f00ca7a0682a0d8074a5989921479d4380b41db206fd9a9faa270a6e78b4716b1dfb174a811a63dc05615390980d1ad2b2977edb4bf664ca681f51553e98483b337478237bea2ae62f73ee9ba50b8821506cc7477d3c0fad9166852856cb8b9728aad1342052660ae6fc7c59d7b1ff178a1b21181b9b869ba8a68578b3c7e68cab4207da3489a28fb188d23b390f502f67284c7765e14570dc519234c003b5ef02005e3236e30a2e0764d34692b52ab6c7d0a8e15536a340cbfef67477bc30266987ba0938da4280aa6b67b369b5126d48618996c55808b6745069b595c3e38bd4752b3cf418ff120cbb9932e3b855f5309b2b7932abe46524e8b8dcf87242b90bbcc1a306d15673dc942373991c68a9369116b92a34203e682ea284a52520e01370bbd69a520a834e7e69f740b977752b5670412a2e08060166a33b7be36bb1f79511cdc89551cc27ed962bb0dc1ea94ed9b06ede14a8a854af1fe10d28f20a433f32ef4b39342389ec569eb2adace45a1c0d3f8934665349bf40d719531a90493c55451198a22740bf9a762001d00206ea57e8b55a852914213ab66201ee4a90ecbc860b052a6bef51661e1401d9b46000500050100000000002b0007061a1a03040303000d00180016090409050906040308040401050308050501080606010017000012e000021f40ff010001000000000e000c0000096c6f63616c686f73740010000e000c02683208687474702f312e312a2a000100","total":1827,"spans":[{"off":0,"len":5,"name":"record header","kind":"frame","note":"TLS record: type 0x16 (handshake), legacy version, length. Rewritten because our edits change the length."},{"off":5,"len":4,"name":"handshake header","kind":"frame","note":"ClientHello (0x01) plus a 3-byte length. Rewritten for the same reason."},{"off":9,"len":2,"name":"legacy_version","kind":"keep","note":"Frozen at 0x0303 since TLS 1.3. The real version lives in supported_versions."},{"off":11,"len":32,"name":"random","kind":"twiddle","note":"32 bytes of client entropy. Re-randomised every connection \u2014 replaying a captured value would repeat one browser's nonce."},{"off":43,"len":33,"name":"legacy_session_id","kind":"twiddle","note":"Chrome sends 32 random bytes on every hello we captured. Re-randomised. The server must echo it, so anything placed here appears twice on the wire."},{"off":76,"len":34,"name":"cipher_suites","kind":"keep","note":"Copied verbatim. Chrome's list and order are part of its fingerprint; changing either is a tell."},{"off":110,"len":2,"name":"compression_methods","kind":"keep","note":"Always the single null method in TLS 1.3."},{"off":112,"len":2,"name":"extensions length","kind":"frame","note":"Recomputed after every edit \u2014 one of five nested lengths that cascade."},{"off":114,"len":4,"name":"GREASE","kind":"keep","note":"RFC 8701 placeholder. Chrome pins one at each end of the extension list; we keep them pinned there while shuffling everything between."},{"off":118,"len":16,"name":"supported_groups","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":134,"len":9,"name":"application_settings","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":143,"len":4,"name":"signed_certificate_timestamp","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":147,"len":6,"name":"psk_key_exchange_modes","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":153,"len":286,"name":"encrypted_client_hello","kind":"twiddle","note":"GREASE ECH. Re-randomised and resized to one of the buckets measured off real Chrome \u2014 186, 218, 250 or 282 bytes, varying per connection independently of SNI length."},{"off":439,"len":7,"name":"compress_certificate","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":446,"len":6,"name":"ec_point_formats","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":452,"len":4,"name":"session_ticket","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":456,"len":1267,"name":"key_share","kind":"twiddle","note":"Fresh X25519 and ML-KEM-768 keys every connection. They must be VALID: filling them with random bytes made real servers reply illegal_parameter, which would have given a censor a replay distinguisher."},{"off":1723,"len":9,"name":"status_request","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":1732,"len":11,"name":"supported_versions","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":1743,"len":28,"name":"signature_algorithms","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":1771,"len":4,"name":"extended_master_secret","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":1775,"len":6,"name":"server_padding","kind":"keep","note":"BoringSSL's 0x12e0, field-trial gated. Present only on established Chrome profiles, and asking for 8000 bytes of server padding obliges the reply to carry it \u2014 so we never depend on it."},{"off":1781,"len":5,"name":"renegotiation_info","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":1786,"len":18,"name":"server_name","kind":"twiddle","note":"Rewritten to the cover domain this egress masquerades as. The only field whose length we change on purpose; the delta cascades through five nested length fields."},{"off":1804,"len":18,"name":"ALPN","kind":"keep","note":"Copied verbatim from the harvested hello."},{"off":1822,"len":5,"name":"GREASE","kind":"keep","note":"RFC 8701 placeholder. Chrome pins one at each end of the extension list; we keep them pinned there while shuffling everything between."}],"extCount":19};

// pre_shared_key is appended by us, so it is not in the harvested bytes. It is
// listed alongside them because from a censor's view it is part of what we emit.
const APPENDED = {
  name: "pre_shared_key",
  kind: "add",
  note: "Appended, not harvested. Carries the authenticator: the ticket is AEAD ciphertext holding the pre-shared key, and the binder is an HMAC over this very hello, truncated at the binders. RFC 8446 requires it last, so appending is the only legal placement — and it turns a full hello into a resumption hello, which is what we want to look like."
};

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
extra.textContent = APPENDED.name + "  (appended)";
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
    paint(APPENDED, "appended after the trailing GREASE", "add");
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
  pnote.textContent = "Chrome permutes its extension order on every single connection — eight connections produced eight distinct orderings. So there is no canonical order to preserve, and appending pre_shared_key is legal against any harvested hello.";
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
