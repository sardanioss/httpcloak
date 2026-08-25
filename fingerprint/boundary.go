package fingerprint

import "crypto/rand"

// boundaryAlphabet is Blink's kAlphaNumericEncodingMap, verbatim: A-Z, a-z,
// 0-9, then 'A' and 'B' again to pad the table to 64 so an index can be taken
// with a 6-bit mask. The duplication is not a mistake, it is what makes 'A' and
// 'B' twice as likely as any other character, and reproducing that means
// reproducing the character distribution as well as the character set.
const boundaryAlphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789AB"

// MultipartBoundary returns a multipart/form-data boundary shaped exactly like
// the one a Chromium browser generates: the literal prefix "----WebKitFormBoundary"
// followed by 16 characters drawn through a 6-bit mask over a 64-entry table.
// Total length 38.
//
// This exists because every binding used to build its own boundary and every
// one of them spelled out the product name in it:
//
//	----HTTPCloakBoundary<uuid4>       (Python)
//	----HTTPCloakBoundary<ts><rand>    (Node)
//	----HttpCloakBoundary<guid>        (.NET)
//
// while Go called multipart.NewWriter with no SetBoundary at all, which emits
// 60 lowercase hex characters and no leading dashes. A boundary travels in the
// content-type REQUEST header, in cleartext above TLS, before a single byte of
// body. It is the cheapest possible identification of a client, needs no probe
// and no statistics, and the capitalisation split even said which binding sent
// it.
//
// Source: third_party/blink/renderer/platform/network/form_data_encoder.cc,
// GenerateUniqueBoundaryString, kPrefix and kRandomSuffixCharacters = 16.
func MultipartBoundary() string {
	const prefix = "----WebKitFormBoundary"
	const n = 16
	b := make([]byte, n)
	// A failure here would be a broken system CSPRNG; the zero value would then
	// produce a constant boundary, which is worse than the bug being fixed, so
	// treat it as fatal rather than degrading silently.
	if _, err := rand.Read(b); err != nil {
		panic("fingerprint: system CSPRNG unavailable: " + err.Error())
	}
	out := make([]byte, 0, len(prefix)+n)
	out = append(out, prefix...)
	for _, v := range b {
		out = append(out, boundaryAlphabet[v&0x3F])
	}
	return string(out)
}
