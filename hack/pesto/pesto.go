// Package pesto is similar to Bazel, except at runtime, for Go programs, containers, and
// tests.
package pesto

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/sirupsen/logrus"
	"golang.org/x/exp/slices"
	"gopkg.in/yaml.v3"

	"zmap.io/portal/hack/data"
)

type BuildDescription struct {
	Targets []Target `yaml:"targets"`
	Files   []FileResource
}

type Target struct {
	Name      string   `yaml:"name"`
	Type      string   `yaml:"type"`
	DependsOn []string `yaml:"depends_on"`
}

// ParseBuildDescriptionFile parses the file at path as a BuildDescription.
func ParseBuildDesciptionFile(path string) (*BuildDescription, error) {
	fd, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer fd.Close()
	return ParseBuildDescription(fd)
}

// ParseBuildDescription returns a BuildDescription from a Reader.
func ParseBuildDescription(r io.Reader) (*BuildDescription, error) {
	bd := new(BuildDescription)
	if err := yaml.NewDecoder(r).Decode(bd); err != nil {
		return nil, err
	}
	return bd, nil
}

func ValidateTargetName(name string) error {
	if name == "" {
		return errors.New("empty target name")
	}
	if strings.Contains(name, "/") {
		return errors.New("target name contains a slash")
	}
	if strings.ContainsRune(name, filepath.Separator) {
		return errors.New("target name contains separator")
	}
	return nil
}

func IsAbsolutePackage(name string) bool {
	return strings.HasPrefix(name, "//")
}

func IsLocalPackage(name string) bool {
	return !strings.Contains(name, "/") && !strings.ContainsRune(name, filepath.Separator)
}

func find(needle int, haystack []int, world map[int][]int) bool {
	if slices.Contains(haystack, needle) {
		return true
	}
	for _, next := range haystack {
		return find(next, world[next], world)
	}
	return false
}

func PackageTargetGraph(pkg string, bd *BuildDescription) error {
	targets := make(map[string]int)
	for i, t := range bd.Targets {
		if err := ValidateTargetName(t.Name); err != nil {
			return err
		}
		targets[t.Name] = i
	}
	deps := make(map[int][]int)

	for i, t := range bd.Targets {
		for _, dn := range t.DependsOn {
			if !IsLocalPackage(dn) {
				logrus.Warnf("skipping non-local package %q", dn)
				continue
			}
			di, ok := targets[dn]
			if !ok {
				return fmt.Errorf("unknown dependency %q of target %q", dn, t.Name)
			}
			if find(i, deps[di], deps) {
				return fmt.Errorf("circular dependcy %q of %q", dn, t.Name)
			}
			deps[i] = append(deps[i], di)
		}
	}
	// TODO(dadrian)[2022-04-16]: Finish this function.
	return nil
}

type FileResource struct {
	Name string `yaml:"name"`
	Path string `yaml:"path"`
}

func (fr *FileResource) validate() error {
	// TODO(dadrian)[2022-04-16]: This should really be a parse
	if fr.Path == "" {
		return errors.New("empty path")
	}
	if strings.Contains(fr.Path, "/") {
		return errors.New("path contains a slash")
	}
	if strings.ContainsRune(fr.Path, filepath.Separator) {
		return errors.New("path contains separator")
	}
	return nil
}

func (fr *FileResource) Load(fsystem fs.FS) (*data.Checksum, error) {
	if err := fr.validate(); err != nil {
		return nil, err
	}
	// d := data.Instance()
	f, err := fsystem.Open(fr.Path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	hr := data.NewHasher()
	t := io.TeeReader(f, hr)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	b, err := io.ReadAll(t)
	if err != nil {
		return nil, err
	}
	ck := hr.Checksum()
	d := data.Instance()
	d.Set(ck, b)
	return &ck, nil
}

type DockerfileContainer struct {
	Context    fs.FS
	Dockerfile []byte
}
