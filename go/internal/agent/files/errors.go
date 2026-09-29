package files

import (
	"errors"
	"io/fs"
	"syscall"
)

// Code is why an operation was refused, as the client sees it.
type Code int

// Codes, POSIX-like, plus tilder's own.
const (
	Denied Code = iota + 1
	NotFound
	Exists
	NotDir
	IsDir
	NotRegular
	Conflict
	Invalid
	NoSpace
	WatchLimit
)

// Error carries a Code; the cause stays in the agent's log.
type Error struct {
	Code  Code
	cause error
}

func (*Error) Error() string   { return "files: refused" }
func (e *Error) Unwrap() error { return e.cause }

func refused(code Code, cause error) error { return &Error{Code: code, cause: cause} }

// CodeOf is the client-facing code for err: Denied for anything unexpected,
// so an error never opens a way through.
func CodeOf(err error) Code {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return Denied
}

// mapErr turns an OS error into a Code; anything unrecognised is Denied.
func mapErr(err error) error {
	var e *Error
	switch {
	case err == nil:
		return nil
	case errors.As(err, &e):
		return err
	case platformCode(err) != 0:
		return refused(platformCode(err), err)
	case errors.Is(err, fs.ErrNotExist):
		return refused(NotFound, err)
	case errors.Is(err, fs.ErrExist):
		return refused(Exists, err)
	case errors.Is(err, syscall.ENOTDIR):
		return refused(NotDir, err)
	case errors.Is(err, syscall.EISDIR):
		return refused(IsDir, err)
	case errors.Is(err, syscall.ENOSPC):
		return refused(NoSpace, err)
	case errors.Is(err, syscall.ENOTEMPTY):
		return refused(Exists, err)
	default:
		return refused(Denied, err) // escapes, permissions, the unexpected
	}
}
