package kravatte

import (
	"fmt"
	"os"
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
	"zmap.io/portal/snp"
)

func runSANSETranscript(t *testing.T, s *sanse, transcript []snp.TranscriptEntry) {
	var plaintext, ciphertext, ad []byte
	var tag [KravatteSANSETagSize]byte
	var recv sanse
	for i, entry := range transcript {
		t.Logf("test %s, entry %d (%s)", t.Name(), i, entry.Action)
		switch entry.Action {
		case "key":
			s.kravatte = Kravatte{}
			s.e = 0
			s.kravatte.RefMaskInitialize(entry.B)
			recv.kravatte = Kravatte{}
			recv.e = 0
			recv.kravatte.RefMaskInitialize(entry.B)
		case "dumpK":
			actual := make([]byte, entry.Length)
			snp.StateExtractBytes(&s.kravatte.k, actual)
			assert.Check(t, cmp.DeepEqual(entry.B, actual), "dumpK")
		case "dumpX":
			actual := make([]byte, entry.Length)
			snp.StateExtractBytes(&s.kravatte.x, actual)
			assert.Check(t, cmp.DeepEqual(entry.B, actual), "dumpX")
		case "dumpY":
			actual := make([]byte, entry.Length)
			snp.StateExtractBytes(&s.kravatte.y, actual)
			assert.Check(t, cmp.DeepEqual(entry.B, actual), "dumpY")
		case "dumpR":
			actual := make([]byte, entry.Length)
			snp.StateExtractBytes(&s.kravatte.kr, actual)
			assert.Check(t, cmp.DeepEqual(entry.B, actual), "dumpR")
		case "dumpQ":
			assert.Check(t, cmp.DeepEqual(entry.B, s.kravatte.q[:]), "dumpQ")
		case "dumpO":
			actual := make([]byte, 8)
			actual[0] = byte(s.kravatte.queueOffsetBits)
			actual[1] = byte(s.kravatte.queueOffsetBits >> 8)
			actual[2] = byte(s.kravatte.queueOffsetBits >> 16)
			actual[3] = byte(s.kravatte.queueOffsetBits >> 24)
			assert.Check(t, cmp.DeepEqual(entry.B, actual), "dumpO")
		case "dumpE":
			actual := make([]byte, 8)
			actual[0] = byte(s.e)
			actual[1] = byte(s.e >> 8)
			actual[2] = byte(s.e >> 16)
			actual[3] = byte(s.e >> 24)
			assert.Check(t, cmp.DeepEqual(entry.B, actual), "dumpE")
		case "plaintext":
			plaintext = make([]byte, len(entry.B))
			copy(plaintext, entry.B)
		case "ad":
			ad = make([]byte, len(entry.B))
			copy(ad, entry.B)
		case "wrap":
			ciphertext = make([]byte, len(plaintext))
			assert.Check(t, cmp.Equal(len(entry.B), len(ciphertext)), "ciphertext length")
			ret := s.wrap(plaintext, ciphertext, 8*len(plaintext), ad, 8*len(ad), tag[:])
			assert.Check(t, cmp.Equal(0, ret))
			assert.Check(t, cmp.DeepEqual(entry.B, ciphertext))
			decrypted := make([]byte, len(ciphertext))
			ret = recv.unwrap(ciphertext, decrypted, 8*len(ciphertext), ad, 8*len(ad), tag[:])
			assert.Check(t, cmp.Equal(0, ret))
			assert.Check(t, cmp.DeepEqual(plaintext, decrypted))
		case "tag":
			assert.Check(t, cmp.DeepEqual(entry.B, tag[:]), "tag")
		default:
			t.Fatalf("unknown action %q", entry.Action)
		}
	}
}

func TestAgainstReference(t *testing.T) {
	implementations := []string{
		"xkcp-sanse",
	}
	for _, implementation := range implementations {
		implementation := implementation
		t.Run(implementation, func(t *testing.T) {
			path := fmt.Sprintf("testdata/%s.txt", implementation)
			r, err := os.Open(path)
			assert.NilError(t, err, "unable to open %s", path)
			transcript := snp.ParseTestTranscript(t, r)
			s := sanse{}
			runSANSETranscript(t, &s, transcript)
		})
	}
}
