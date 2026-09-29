package transfer

import (
	"testing"

	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

func entry(path string, kind tilderv1.FsKind) *tilderv1.XferEntry {
	e := &tilderv1.XferEntry{Path: []byte(path), Kind: kind}
	if kind == tilderv1.FsKind_FS_KIND_SYMLINK {
		e.LinkTarget = []byte("t")
	}
	return e
}

// Nothing is made from a manifest whose names could leave the part, collide,
// or hang under something that is not a directory listed before them.
func TestAManifestThatCouldLeaveThePartIsRefused(t *testing.T) {
	t.Parallel()
	const (
		dir  = tilderv1.FsKind_FS_KIND_DIR
		file = tilderv1.FsKind_FS_KIND_FILE
		link = tilderv1.FsKind_FS_KIND_SYMLINK
	)
	root := entry("", dir)
	for name, c := range map[string]struct {
		entries []*tilderv1.XferEntry
		ok      bool
	}{
		"a folder":               {[]*tilderv1.XferEntry{root, entry("a", dir), entry("a/b.txt", file), entry("l", link)}, true},
		"a single file":          {[]*tilderv1.XferEntry{entry("", file)}, true},
		"empty":                  {nil, false},
		"the root has a name":    {[]*tilderv1.XferEntry{entry("x", dir)}, false},
		"a name going up":        {[]*tilderv1.XferEntry{root, entry("../x", file)}, false},
		"a name going up inside": {[]*tilderv1.XferEntry{root, entry("a", dir), entry("a/../../x", file)}, false},
		"an absolute name":       {[]*tilderv1.XferEntry{root, entry("/etc/passwd", file)}, false},
		"a dot":                  {[]*tilderv1.XferEntry{root, entry(".", file)}, false},
		"an empty part":          {[]*tilderv1.XferEntry{root, entry("a", dir), entry("a//b", file)}, false},
		"a NUL":                  {[]*tilderv1.XferEntry{root, entry("a\x00b", file)}, false},
		"a name twice":           {[]*tilderv1.XferEntry{root, entry("a", file), entry("a", file)}, false},
		"under a link":           {[]*tilderv1.XferEntry{root, entry("l", link), entry("l/x", file)}, false},
		"under a file":           {[]*tilderv1.XferEntry{root, entry("f", file), entry("f/x", file)}, false},
		"before its directory":   {[]*tilderv1.XferEntry{root, entry("a/b", file), entry("a", dir)}, false},
		"under a single file":    {[]*tilderv1.XferEntry{entry("", file), entry("x", file)}, false},
		"a special file":         {[]*tilderv1.XferEntry{root, entry("p", tilderv1.FsKind_FS_KIND_OTHER)}, false},
		"a link to nothing":      {[]*tilderv1.XferEntry{root, {Path: []byte("l"), Kind: link}}, false},
	} {
		if err := validate(c.entries); (err == nil) != c.ok {
			t.Errorf("%s: validate = %v, want ok=%v", name, err, c.ok)
		}
	}
}
