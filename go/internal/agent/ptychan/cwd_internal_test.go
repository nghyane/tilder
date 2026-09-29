package ptychan

import "testing"

// A folder under the home goes relative, as the fs channel takes it; one
// outside goes absolute and marked, to be shown and never started in.
func TestAFolderIsSaidRelativeToTheHome(t *testing.T) {
	t.Parallel()
	for dir, want := range map[string]struct {
		dir     string
		outside bool
	}{
		"/home/me":             {"", false},
		"/home/me/src/api":     {"src/api", false},
		"/home/me/..hidden":    {"..hidden", false},
		"/etc":                 {"/etc", true},
		"/home/meander":        {"/home/meander", true},
		"/home/me/../me2/data": {"/home/me/../me2/data", true},
	} {
		got := place("/home/me", dir)
		if string(got.GetDir()) != want.dir || got.GetOutsideHome() != want.outside {
			t.Errorf("%s: %q outside=%v, want %q outside=%v", dir, got.GetDir(), got.GetOutsideHome(), want.dir, want.outside)
		}
	}
}
