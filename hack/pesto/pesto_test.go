package pesto

import (
	"testing"

	"gotest.tools/assert"

	"zmap.io/portal/hack/data"
)

func TestFileResource(t *testing.T) {
	bd, err := ParseBuildDesciptionFile("testdata/base_itest.yaml")
	assert.NilError(t, err)
	d := data.Instance()
	fsystem, err := d.PackageSourceFS("//hack/pesto/testdata")
	assert.NilError(t, err)
	ck, err := bd.Files[0].Load(fsystem)
	assert.NilError(t, err)
	assert.Equal(t, *ck, data.ChecksumHexString("bee0f829bc62481d240d23a07cc1971867943ea1beeac2d293fa5691b0bc3fc7"))

	err = PackageTargetGraph("//hack/pesto/testdata", bd)
	assert.NilError(t, err)

}
