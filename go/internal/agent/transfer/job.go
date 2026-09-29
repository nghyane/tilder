// Package transfer is the destination of a copy between machines (ADR 0035):
// it pulls what a grant names from the source machine into a part directory
// beside the destination, resumes after a cut or a restart, and puts the copy
// in place only when every chunk arrived and was checked.
package transfer

import (
	"context"
	"encoding/base64"
	"errors"
	"io"
	"io/fs"
	"log/slog"
	"math/rand/v2"
	"os"
	"sync"
	"syscall"
	"time"

	"github.com/nghyane/tilder/go/internal/agent/files"
	"github.com/nghyane/tilder/go/internal/clock"
	"github.com/nghyane/tilder/go/internal/identity"
	tilderv1 "github.com/nghyane/tilder/go/internal/wire/tilder/v1"
)

const (
	dialTimeout = 30 * time.Second
	maxBackoff  = 60 * time.Second
	saveEvery   = time.Second
	reportEvery = 250 * time.Millisecond
	// maxAgain bounds reconnecting at once because the source's files keep
	// changing under the copy.
	maxAgain = 5
)

// Conn is the `xfer` channel to the source.
type Conn interface {
	io.ReadWriteCloser
	// Relayed reports whether the connection goes through a TURN relay.
	Relayed() bool
}

// Connect reaches the source machine for the copy; ctx bounds one attempt.
type Connect func(ctx context.Context) (Conn, error)

// Progress is how far a copy got.
type Progress struct {
	ID               string
	Name             []byte
	Bytes, Total     uint64
	Files, FilesDone uint32
	Relayed          bool
	// Waiting: for the source machine, offline or being reached.
	Waiting bool
	// Ended: done when Code is unspecified, failed otherwise.
	Ended bool
	Code  tilderv1.XferFailed_Code
}

// Job is one copy arriving on this machine.
type Job struct {
	Grant identity.Transfer
	// Raw is the grant message as received, kept to resume after a restart.
	Raw     []byte
	Tree    *files.Tree
	Connect Connect
	Clock   clock.Clock
	Log     *slog.Logger
	// OnProgress is told how far the copy got, a few times a second, and
	// when it ends.
	OnProgress func(Progress)
	// Recheck judges the grant again before each connection (ADR 0040): an
	// error wrapping ErrNotYet waits for a newer list of removed devices, any
	// other ends the copy. Nil checks nothing.
	Recheck func() error

	chanOnce   sync.Once
	cancelOnce sync.Once
	cancelled  chan struct{}

	// Owned by Run's goroutine.
	part       part
	entries    []*tilderv1.XferEntry
	done       []bool
	partial    map[uint32]uint64
	cur        *os.File
	curIndex   uint32
	lastSave   time.Time
	lastReport time.Time
	relayed    bool
	again      int
}

// failure ends a copy for good, with the code the owner sees.
type failure struct{ code tilderv1.XferFailed_Code }

func (f failure) Error() string { return "transfer: " + f.code.String() }

var (
	// errAgain: reconnect at once and list again (a file changed).
	errAgain    = errors.New("transfer: the source changed; listing again")
	errProtocol = errors.New("transfer: the source broke the protocol")
)

// Cancel stops the copy and removes what arrived. It is idempotent, and
// safe from any goroutine.
func (j *Job) Cancel() {
	j.initChan()
	j.cancelOnce.Do(func() { close(j.cancelled) })
}

func (j *Job) initChan() { j.chanOnce.Do(func() { j.cancelled = make(chan struct{}) }) }

// Run copies until the copy is done or fails, and returns how it ended. When
// ctx ends first (the agent stopping) the part stays, to be resumed, and the
// progress returned is not Ended.
func (j *Job) Run(ctx context.Context) Progress {
	j.initChan()
	jctx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		select {
		case <-j.cancelled:
			stop()
		case <-jctx.Done():
		}
	}()
	code, ended := j.run(jctx)
	p := j.progress()
	p.Ended, p.Code = ended, code
	j.report(p, true)
	return p
}

func (j *Job) run(ctx context.Context) (tilderv1.XferFailed_Code, bool) {
	dst := string(j.Grant.DstPath)
	if !cleanPath(dst) {
		return tilderv1.XferFailed_CODE_DENIED, true
	}
	dir, err := j.Tree.OpenDir(parentOf(dst))
	if err != nil {
		return tilderv1.XferFailed_CODE_NOT_FOUND, true
	}
	defer func() { _ = dir.Close() }()
	j.part = part{dir: dir, name: baseOf(dst), at: files.PartDir + "/" + j.Grant.ID()}
	if oerr := j.part.open(j.Raw); oerr != nil {
		return codeOf(oerr), true
	}
	if j.entries, j.done, j.partial, err = j.part.load(); err != nil {
		j.Log.Warn("starting a copy over: its saved state could not be read", slog.Any("error", err))
		j.part.remove()
		if oerr := j.part.open(j.Raw); oerr != nil {
			return codeOf(oerr), true
		}
		j.entries = nil
	}
	defer j.closeCur()
	attempt := 0
	for {
		if code, ended := j.stopped(ctx); ended || ctx.Err() != nil {
			return code, ended
		}
		j.report(Progress{Waiting: true}, true)
		if j.Recheck != nil {
			if rerr := j.Recheck(); errors.Is(rerr, ErrNotYet) {
				j.wait(ctx, attempt)
				attempt++
				continue
			} else if rerr != nil {
				j.closeCur()
				j.part.remove()
				return tilderv1.XferFailed_CODE_DENIED, true
			}
		}
		before := j.progress().Bytes
		err := j.attempt(ctx)
		if err == nil {
			return j.finish()
		}
		var f failure
		if errors.As(err, &f) {
			j.part.remove()
			return f.code, true
		}
		if j.progress().Bytes > before {
			attempt, j.again = 0, 0
		}
		if errors.Is(err, errAgain) {
			if j.again++; j.again > maxAgain {
				j.part.remove()
				return tilderv1.XferFailed_CODE_CHANGED, true
			}
			continue
		}
		j.Log.Info("copy interrupted; reconnecting", slog.String("transfer", j.Grant.ID()), slog.Any("error", err))
		j.wait(ctx, attempt)
		attempt++
	}
}

// stopped says whether the copy must end now: cancelled (the part removed),
// out of time, or the agent stopping (the part kept, not ended).
func (j *Job) stopped(ctx context.Context) (tilderv1.XferFailed_Code, bool) {
	select {
	case <-j.cancelled:
		j.closeCur()
		j.part.remove()
		return tilderv1.XferFailed_CODE_CANCELLED, true
	default:
	}
	if ctx.Err() != nil {
		j.save()
		return tilderv1.XferFailed_CODE_UNSPECIFIED, false
	}
	if j.Clock.Now().After(j.Grant.NotAfter) {
		j.closeCur()
		j.part.remove()
		return tilderv1.XferFailed_CODE_EXPIRED, true
	}
	return tilderv1.XferFailed_CODE_UNSPECIFIED, false
}

// attempt is one connection: reach the source, then pull.
func (j *Job) attempt(ctx context.Context) error {
	cctx, cancel := context.WithTimeout(ctx, dialTimeout)
	conn, err := j.Connect(cctx)
	cancel()
	if err != nil {
		return err
	}
	defer func() { _ = conn.Close() }()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	j.relayed = conn.Relayed()
	err = j.pull(conn)
	j.save()
	return err
}

// wait is 1 s doubling to 60 s, ±30 %, or until ctx ends.
func (j *Job) wait(ctx context.Context, attempt int) {
	base := min(time.Second<<min(attempt, 6), maxBackoff)
	d := time.Duration(float64(base) * (0.7 + 0.6*rand.Float64())) //nolint:gosec // G404: jitter, not a secret
	t := j.Clock.NewTimer(d, "transfer", "reconnect")
	defer t.Stop()
	select {
	case <-ctx.Done():
	case <-t.C:
	}
}

// finish gives each directory its permissions and time, deepest first, puts
// the copy in place and removes the part.
func (j *Job) finish() (tilderv1.XferFailed_Code, bool) {
	j.closeCur()
	for i := len(j.entries) - 1; i >= 0; i-- {
		if e := j.entries[i]; e.GetKind() == tilderv1.FsKind_FS_KIND_DIR {
			p := j.part.item(string(e.GetPath()))
			_ = j.part.dir.Chmod(p, fs.FileMode(e.GetPerm())&fs.ModePerm|0o700)
			mtime := time.Unix(0, e.GetMtimeNs())
			_ = j.part.dir.Chtimes(p, mtime, mtime)
		}
	}
	raw := j.Grant.Device.Raw32()
	name, err := j.part.place(j.entries[0].GetKind(), j.Clock.Now(), base64.RawURLEncoding.EncodeToString(raw[:])[:6])
	if err != nil {
		j.Log.Warn("could not put a finished copy in place", slog.Any("error", err))
		return codeOf(err), true
	}
	j.part.name = name
	j.part.remove()
	return tilderv1.XferFailed_CODE_UNSPECIFIED, true
}

func (j *Job) progress() Progress {
	p := Progress{ID: j.Grant.ID(), Name: []byte(j.part.name), Relayed: j.relayed}
	for i, e := range j.entries {
		if e.GetKind() != tilderv1.FsKind_FS_KIND_FILE {
			continue
		}
		p.Files++
		p.Total += e.GetSize()
		switch {
		case j.done[i]:
			p.FilesDone++
			p.Bytes += e.GetSize()
		default:
			p.Bytes += min(j.partial[uint32(i)]*chunkSize, e.GetSize()) //nolint:gosec // G115: i < maxEntries
		}
	}
	return p
}

// report tells OnProgress, at most every reportEvery unless forced.
func (j *Job) report(p Progress, force bool) {
	if j.OnProgress == nil {
		return
	}
	now := j.Clock.Now()
	if !force && now.Sub(j.lastReport) < reportEvery {
		return
	}
	j.lastReport = now
	if p.ID == "" {
		waiting := p.Waiting
		p = j.progress()
		p.Waiting = waiting
	}
	j.OnProgress(p)
}

// codeOf is the code the owner sees for a disk error.
func codeOf(err error) tilderv1.XferFailed_Code {
	var fe *files.Error
	switch {
	case errors.Is(err, syscall.ENOSPC), errors.Is(err, syscall.EDQUOT):
		return tilderv1.XferFailed_CODE_NO_SPACE
	case errors.Is(err, fs.ErrNotExist):
		return tilderv1.XferFailed_CODE_NOT_FOUND
	case errors.Is(err, fs.ErrPermission), errors.As(err, &fe):
		return tilderv1.XferFailed_CODE_DENIED
	default:
		return tilderv1.XferFailed_CODE_INTERNAL
	}
}

func slogErr(err error) slog.Attr { return slog.Any("error", err) }
