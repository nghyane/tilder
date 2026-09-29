//go:build windows

package transfer

// syscallNoFollow: Go's os.Root on Windows opens the last name without
// following a reparse point already (FILE_OPEN_REPARSE_POINT), and
// part.under refuses a link on the way (ADR 0044).
const syscallNoFollow = 0
