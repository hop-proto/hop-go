package agent

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"zmap.io/portal/common"
	"zmap.io/portal/keys"
)

// Data is the data access object for all of the Agent.
type Data struct {
	Keys map[string]*keys.X25519KeyPair
}

// Init loads keys into the data object from the Hop configuration directory.
func (d *Data) Init() error {
	d.Keys = make(map[string]*keys.X25519KeyPair)
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, common.UserConfigDirtory)
	err = filepath.WalkDir(dir, func(path string, entry fs.DirEntry, _ error) error {
		if path == dir {
			return nil
		}
		if entry != nil && entry.IsDir() {
			return filepath.SkipDir
		}
		if strings.ToLower(filepath.Ext(path)) != ".pem" {
			logrus.Debugf("skipping path %s, not a .pem file", path)
			return nil
		}
		k, err := keys.ReadDHKeyFromPEMFile(path)
		if err != nil {
			logrus.Errorf("%s: %s", path, err)
			return nil
		}
		d.Keys[path] = k
		return nil
	})
	if err != nil {
		return err
	}
	logrus.Infof("loaded %d keys", len(d.Keys))
	return nil
}
