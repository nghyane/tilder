package transfer

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"

	"github.com/nghyane/tilder/go/internal/agent/files"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

// part is a copy arriving, in the directory it goes to (ADR 0035):
//
//	.tilder-part/<id>/grant     the grant, as received: resumed after a restart
//	.tilder-part/<id>/manifest  what the source listed, as one message
//	.tilder-part/<id>/state     how far each file got; written only after the
//	                            data it counts is synced
//	.tilder-part/<id>/item      the copy, built in place, renamed at the end
//
// Everything goes through dir, a root: no name the source sent leaves it.
type part struct {
	dir  *os.Root
	name string // the copy's final name in dir
	at   string // .tilder-part/<id>
}

// state is how far the copy got: files done, and chunks written and checked
// of the files begun, by manifest index.
type state struct {
	V       int               `json:"v"`
	Done    string            `json:"done"` // base64url bitset
	Partial map[uint32]uint64 `json:"partial,omitempty"`
}

const stateVersion = 1

func (p *part) item(rel string) string {
	if rel == "" {
		return p.at + "/item"
	}
	return p.at + "/item/" + rel
}

// under checks that every directory between the item and rel is a real
// directory, never a link: os.Root follows a link that stays inside the
// root, and the root here is the destination's parent. A source that sends
// "A" as a link to ../../.tilder, then "a/key", on a disk that folds case or
// normalizes names (APFS), would otherwise write through the link.
func (p *part) under(rel string) error {
	at := p.item("")
	for part := range strings.SplitSeq(parentOf(rel), "/") {
		if part == "" {
			continue
		}
		at += "/" + part
		info, err := p.dir.Lstat(at)
		if err != nil {
			return err
		}
		if !info.IsDir() {
			return errBadManifest
		}
	}
	return nil
}

// open makes the part's directory, keeping the grant in it; an existing one
// is resumed.
func (p *part) open(grant []byte) error {
	if err := p.dir.MkdirAll(p.at, 0o700); err != nil {
		return err
	}
	if _, err := p.dir.Stat(p.at + "/grant"); err == nil {
		return nil
	}
	return p.writeAtomic("grant", grant)
}

// load reads a manifest and state kept by an earlier run; none is not an error.
func (p *part) load() ([]*tilderv1.XferEntry, []bool, map[uint32]uint64, error) {
	raw, err := p.dir.ReadFile(p.at + "/manifest")
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil, nil, nil
	}
	if err != nil {
		return nil, nil, nil, err
	}
	m := &tilderv1.XferManifest{}
	if uerr := proto.Unmarshal(raw, m); uerr != nil {
		return nil, nil, nil, uerr
	}
	if verr := validate(m.GetEntries()); verr != nil {
		return nil, nil, nil, verr
	}
	var st state
	raw, err = p.dir.ReadFile(p.at + "/state")
	if err == nil {
		err = json.Unmarshal(raw, &st)
	}
	done := make([]bool, len(m.GetEntries()))
	if err != nil || st.V != stateVersion {
		return m.GetEntries(), done, map[uint32]uint64{}, nil //nolint:nilerr // an unreadable state starts the files over, keeping the manifest
	}
	bits, _ := base64.RawURLEncoding.DecodeString(st.Done)
	for i := range done {
		done[i] = i/8 < len(bits) && bits[i/8]&(1<<(i%8)) != 0
	}
	partial := map[uint32]uint64{}
	for i, n := range st.Partial {
		if int(i) < len(done) {
			partial[i] = n
		}
	}
	return m.GetEntries(), done, partial, nil
}

func (p *part) saveManifest(entries []*tilderv1.XferEntry) error {
	raw, err := proto.Marshal(&tilderv1.XferManifest{Entries: entries, Last: true})
	if err != nil {
		return err
	}
	return p.writeAtomic("manifest", raw)
}

func (p *part) saveState(done []bool, partial map[uint32]uint64) error {
	bits := make([]byte, (len(done)+7)/8)
	for i, d := range done {
		if d {
			bits[i/8] |= 1 << (i % 8)
		}
	}
	raw, err := json.Marshal(state{V: stateVersion, Done: base64.RawURLEncoding.EncodeToString(bits), Partial: partial})
	if err != nil {
		return err
	}
	return p.writeAtomic("state", raw)
}

// writeAtomic replaces the part's file name: written, synced, renamed.
func (p *part) writeAtomic(name string, data []byte) error {
	tmp := p.at + "/" + name + ".tmp"
	f, err := p.dir.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC|syscallNoFollow, 0o600)
	if err != nil {
		return err
	}
	_, err = f.Write(data)
	if err == nil {
		err = f.Sync()
	}
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return err
	}
	return p.dir.Rename(tmp, p.at+"/"+name)
}

// place moves the finished copy to its name. A name taken since the copy
// began is kept: the copy gets a conflict name beside it, never replacing
// anything (the console chose a free name; this is the safety net).
func (p *part) place(kind tilderv1.FsKind, now time.Time, device string) (string, error) {
	name := p.name
	if _, err := p.dir.Lstat(name); err == nil {
		name = conflictName(p.name, kind == tilderv1.FsKind_FS_KIND_FILE, now, device)
	}
	from := p.item("")
	if kind == tilderv1.FsKind_FS_KIND_FILE {
		// A hard link fails if the name exists: nothing is replaced, even in a race.
		if err := p.dir.Link(from, name); err != nil {
			return "", err
		}
		return name, p.dir.Remove(from)
	}
	if _, err := p.dir.Lstat(name); err == nil {
		return "", &files.Error{Code: files.Exists}
	}
	return name, p.dir.Rename(from, name)
}

// remove deletes the part, and .tilder-part when nothing else is arriving.
func (p *part) remove() {
	_ = p.dir.RemoveAll(p.at)
	_ = p.dir.Remove(files.PartDir)
}

// conflictName is <stem>.tilder-conflict-YYYYMMDD-HHMMSS-<dev><ext>.
func conflictName(name string, file bool, now time.Time, device string) string {
	stem, ext := name, ""
	if file {
		if e := path.Ext(name); e != "" && e != name {
			stem, ext = strings.TrimSuffix(name, e), e
		}
	}
	return stem + ".tilder-conflict-" + now.Format("20060102-150405") + "-" + device + ext
}
