package kravatte

import (
	"encoding/hex"
	"fmt"
	"os"
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
	"hop.computer/hop/snp"
)

func newTestKey(n int) []byte {
	out := make([]byte, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, byte(i))
	}
	return out
}

func TestRefMask(t *testing.T) {
	expectedK, _ := hex.DecodeString("d7043ed821cbe5eea9642ba0a3a9fec839f6cc1c52bccb5d85f42c5d3306251e6ede291c272e534f540b90c54fcf377918367d714b9384fdb8f4330d49db73466f8450101da9fe4e3f866b6c962c211a93aba9a1549b6711565851748ee4589d5a0323fcfc117e71a0dabbc12baaf9a25d3447b3d8c9c142dd3ade5cac86d252d2f268268d5d3a420bb6dd482aeeff4697fde226fe32df06cd7600937137626efb5d7040b03d4a37da5c9c687eaba785d544d5c5d175ef2b36e2ea4e56391596362e81b387b4deb2")
	var expectedKLanes [25]uint64
	snp.StateSetBytes(&expectedKLanes, expectedK)
	key := newTestKey(16)
	kv := Kravatte{}
	kv.x[1] = 1
	kv.RefMaskInitialize(key)
	t.Logf("% x", kv.k)
	assert.Check(t, cmp.DeepEqual(expectedKLanes, kv.k))
	assert.Check(t, cmp.DeepEqual(kv.kr, kv.k))
	assert.Check(t, cmp.DeepEqual(kv.x, zero))
}

func runTranscript(t *testing.T, kv *Kravatte, transcript []snp.TranscriptEntry) {
	var buf []byte
	for i, entry := range transcript {
		t.Logf("test %s, entry %d (%s)", t.Name(), i, entry.Action)
		switch entry.Action {
		case "key":
			kv.RefMaskInitialize(entry.B)
		case "in":
			ret := kv.Kra(entry.B, 8*len(entry.B), FlagNone)
			assert.Check(t, cmp.Equal(0, ret), "Kra/None")
		case "inbits":
			ret := kv.Kra(entry.B, entry.Length, FlagLastPart)
			assert.Check(t, cmp.Equal(0, ret), "Kra/None/Bits")
		case "last":
			ret := kv.Kra(entry.B, 8*len(entry.B), FlagLastPart)
			assert.Check(t, cmp.Equal(0, ret), "Kra/Last")
		case "out":
			out := make([]byte, entry.Length)
			ret := kv.Vatte(out, 8*len(out), FlagNone)
			assert.Check(t, cmp.Equal(0, ret), "Vatte")
			assert.Check(t, cmp.DeepEqual(entry.B, out), "out")
		case "kravatin":
			buf = make([]byte, 16)
			ret := kv.Kravatte(entry.B, buf, FlagLastPart)
			assert.Check(t, cmp.Equal(0, ret), "KraVatte/In")
		case "kravatout":
			assert.Check(t, cmp.DeepEqual(entry.B, buf), "KraVatte/Out")
		case "dumpK":
			actual := make([]byte, entry.Length)
			snp.StateExtractBytes(&kv.k, actual)
			assert.Check(t, cmp.DeepEqual(entry.B, actual), "dumpK")
		case "dumpX":
			actual := make([]byte, entry.Length)
			snp.StateExtractBytes(&kv.x, actual)
			assert.Check(t, cmp.DeepEqual(entry.B, actual), "dumpX")
		case "dumpY":
			actual := make([]byte, entry.Length)
			snp.StateExtractBytes(&kv.y, actual)
			assert.Check(t, cmp.DeepEqual(entry.B, actual), "dumpY")
		case "dumpR":
			actual := make([]byte, entry.Length)
			snp.StateExtractBytes(&kv.kr, actual)
			assert.Check(t, cmp.DeepEqual(entry.B, actual), "dumpR")
		case "dumpQ":
			assert.Check(t, cmp.DeepEqual(entry.B, kv.q[:]), "dumpQ")
		case "dumpO":
			actual := make([]byte, 8)
			actual[0] = byte(kv.queueOffsetBits)
			actual[1] = byte(kv.queueOffsetBits >> 8)
			actual[2] = byte(kv.queueOffsetBits >> 16)
			actual[3] = byte(kv.queueOffsetBits >> 24)
			assert.Check(t, cmp.DeepEqual(entry.B, actual), "dumpO")
		default:
			t.Fatalf("unknown action %q", entry.Action)
		}
	}
}

func TestKravatteAgainstReference(t *testing.T) {
	implementations := []string{
		"xkcp-kravatte",
	}
	for _, implementation := range implementations {
		implementation := implementation
		t.Run(implementation, func(t *testing.T) {
			path := fmt.Sprintf("testdata/%s.txt", implementation)
			r, err := os.Open(path)
			assert.NilError(t, err, "unable to open %s", path)
			transcript := snp.ParseTestTranscript(t, r)
			k := Kravatte{}
			runTranscript(t, &k, transcript)
		})
	}
}
