//go:build windows

package files

// openNonblock: Windows opens no FIFO or device through a path under the
// home that could block the way a Unix one does.
const openNonblock = 0
