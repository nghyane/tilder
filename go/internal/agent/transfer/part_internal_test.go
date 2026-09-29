package transfer

import (
	"os"
	"path/filepath"
	"testing"

	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// partWithLink is a copy's part whose item holds "A", a link up to the
// agent's directory, as a source can make it; key is the file it must not
// reach.
func partWithLink(t *testing.T) (j *Job, key string) {
	t.Helper()
	h := t.TempDir()
	key = filepath.Join(h, ".tilder", "key")
	if err := os.MkdirAll(filepath.Dir(key), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(key, []byte("machine key"), 0o600); err != nil {
		t.Fatal(err)
	}
	item := filepath.Join(h, ".tilder-part", "x", "item")
	if err := os.MkdirAll(item, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../../.tilder", filepath.Join(item, "A")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(h)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return &Job{part: part{dir: root, at: ".tilder-part/x"}}, key
}

// Nothing a copy makes goes through a link in its part, whatever name
// reached it: os.Root follows a link that stays inside the destination.
func TestNothingIsMadeThroughALinkInThePart(t *testing.T) {
	t.Parallel()
	j, key := partWithLink(t)
	if err := j.make(entry("A/made", tilderv1.FsKind_FS_KIND_DIR)); err == nil {
		t.Fatal("made a directory through the link")
	}
	j.entries = []*tilderv1.XferEntry{entry("", tilderv1.FsKind_FS_KIND_DIR), entry("A/key", tilderv1.FsKind_FS_KIND_FILE)}
	if f, err := j.openFile(1, 0); err == nil {
		_ = f.Close()
		t.Fatal("opened a file through the link")
	}
	if b, err := os.ReadFile(key); err != nil || string(b) != "machine key" { //nolint:gosec // G304: the test's temp dir
		t.Fatalf("the key = %q, %v", b, err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(key), "made")); err == nil {
		t.Fatal("a directory appeared in the agent's directory")
	}
}

// On a disk that folds case (APFS by default), "A" and "a" are one name: a
// manifest listing the link "A" and then the directory "a" is refused, not
// followed into the agent's directory.
func TestACaseFoldedNameDoesNotReachThroughALink(t *testing.T) {
	t.Parallel()
	j, key := partWithLink(t)
	if _, err := j.part.dir.Lstat(j.part.item("a")); err != nil {
		t.Skip("this disk tells A from a")
	}
	link := &tilderv1.XferEntry{Path: []byte("A"), Kind: tilderv1.FsKind_FS_KIND_SYMLINK, LinkTarget: []byte("../../../.tilder")}
	j.entries = []*tilderv1.XferEntry{entry("", tilderv1.FsKind_FS_KIND_DIR), link}
	if err := j.make(entry("a", tilderv1.FsKind_FS_KIND_DIR)); err == nil {
		t.Fatal("took the link A for the directory a")
	}
	j.entries = append(j.entries, entry("a", tilderv1.FsKind_FS_KIND_DIR), entry("a/key", tilderv1.FsKind_FS_KIND_FILE))
	if f, err := j.openFile(3, 0); err == nil {
		_ = f.Close()
		t.Fatal("wrote a/key through the link A")
	}
	if b, err := os.ReadFile(key); err != nil || string(b) != "machine key" { //nolint:gosec // G304: the test's temp dir
		t.Fatalf("the key = %q, %v", b, err)
	}
}

// A manifest is refused as its pages come: one long name, too many bytes in
// all, or pages that never end, before the destination holds it all.
func TestAManifestTooLargeIsRefusedAsItComes(t *testing.T) {
	t.Parallel()
	page := func(entries ...*tilderv1.XferEntry) *tilderv1.XferServer {
		return &tilderv1.XferServer{Msg: &tilderv1.XferServer_Manifest{Manifest: &tilderv1.XferManifest{Entries: entries, ChunkSize: chunkSize}}}
	}
	long := &tilderv1.XferEntry{Path: make([]byte, maxPath+1), Kind: tilderv1.FsKind_FS_KIND_FILE}
	sent := 0
	_, err := readManifest(func() (*tilderv1.XferServer, error) {
		sent++
		return page(long), nil
	})
	if err == nil || sent != 1 {
		t.Fatalf("a long name: %v after %d pages, want refused at the first", err, sent)
	}
	sent = 0
	big := &tilderv1.XferEntry{Path: make([]byte, maxPath), Kind: tilderv1.FsKind_FS_KIND_FILE}
	_, err = readManifest(func() (*tilderv1.XferServer, error) {
		sent++
		return page(big, big, big, big), nil
	})
	if err == nil || sent*4*maxPath > maxManifestBytes+4*maxPath {
		t.Fatalf("names adding up: %v after %d pages", err, sent)
	}
	sent = 0
	_, err = readManifest(func() (*tilderv1.XferServer, error) {
		sent++
		return page(), nil
	})
	if err == nil || sent > maxEntries+1 {
		t.Fatalf("empty pages: %v after %d", err, sent)
	}
}
