package kravatte

import (
	"encoding/hex"
	"testing"

	"gotest.tools/assert"
	"gotest.tools/assert/cmp"
	"zmap.io/portal/snp"
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
	assert.Check(t, cmp.DeepEqual(kv.r, kv.k))
	assert.Check(t, cmp.DeepEqual(kv.x, zero))
}

func TestKra(t *testing.T) {
	key := newTestKey(16)
	kv := Kravatte{}
	kv.RefMaskInitialize(key)
	kv.Kra([]byte("Kravatte! Kravatte! Kra! Kra! Kra!"), FlagNone)
	t.Logf("x: %x", kv.x)
	t.Logf("r: %x", kv.r)
	t.Logf("k: %x", kv.k)
	t.Fail()
}
