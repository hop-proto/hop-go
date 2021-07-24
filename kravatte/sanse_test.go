package kravatte

import (
	"crypto/cipher"
	"fmt"
	"io/ioutil"
	"os"
	"testing"

	"github.com/sirupsen/logrus"
	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
	"zmap.io/portal/snp"
)

func runSANSETranscript(t *testing.T, s *sanse, transcript []snp.TranscriptEntry) {
	var plaintext, ciphertext, ad []byte
	var tag [TagSize]byte
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

type communicationDirection int

const (
	i2r communicationDirection = 0
	r2i communicationDirection = 1
)

type aeadTranscriptEntry struct {
	plaintext string
	direction communicationDirection
}

func mustReadFileToString(path string) string {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		logrus.Panicf("unable to read file %q: %s", path, err)
	}
	return string(content)
}

func allocateForSeal(plaintext string, alias bool) (src, dst []byte) {
	dst = make([]byte, len(plaintext)+TagSize)
	if alias {
		copy(dst, []byte(plaintext))
		return dst[:len(plaintext)], dst[:0]
	}
	return []byte(plaintext), dst[:0]
}

func allocateForOpen(ciphertext []byte, alias bool) (src, dst []byte) {
	if alias {
		return ciphertext, ciphertext[:0]
	}
	dst = make([]byte, len(ciphertext)-TagSize)
	return ciphertext, dst[:0]
}

func TestAEAD(t *testing.T) {
	transcript := []aeadTranscriptEntry{
		{
			plaintext: "The quick brown fox jumps over the lazy dog",
			direction: i2r,
		},
		{
			plaintext: "If you will it, dude, it is no dream.",
			direction: i2r,
		},
		{
			plaintext: mustReadFileToString("testdata/rfc8446.txt"),
			direction: r2i,
		},
		{
			plaintext: "I miss SSLv2",
			direction: i2r,
		},
	}
	key := newTestKey(32)
	initiator, err := NewSANSE(key)
	assert.NilError(t, err)
	responder, err := NewSANSE(key)
	assert.NilError(t, err)
	var associatedData [1]byte

	runTranscript := func(alias bool) func(t *testing.T) {
		return func(t *testing.T) {
			for i, e := range transcript {
				t.Logf("entry %d (direction %d)", i, e.direction)
				associatedData[0] = byte(e.direction)
				var s, r cipher.AEAD
				switch e.direction {
				case i2r:
					s = initiator
					r = responder
				case r2i:
					s = responder
					r = initiator
				default:
					t.Fatalf("unknown direction %d", e.direction)
				}
				plaintext, ciphertext := allocateForSeal(e.plaintext, alias)
				ciphertext = s.Seal(ciphertext, nil, plaintext, associatedData[:])

				var err error
				ciphertext, decrypted := allocateForOpen(ciphertext, alias)
				decrypted, err = r.Open(decrypted, nil, ciphertext, associatedData[:])
				assert.Check(t, err, "error decrypting on entry index %d", i)
				assert.Check(t, cmp.DeepEqual([]byte(e.plaintext), decrypted))
			}
		}
	}
	t.Run("no alias", runTranscript(false))
	t.Run("with alias", runTranscript(true))
}
