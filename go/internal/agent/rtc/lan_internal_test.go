package rtc

import (
	"net/netip"
	"testing"
)

// ADR 0039: only a pair inside one LAN moves a copy to TCP; a pair across
// the internet keeps it on the data channel.
func TestOnlyAPairInsideOneLANIsTheLAN(t *testing.T) {
	t.Parallel()
	for _, c := range []struct {
		a, b string
		want bool
	}{
		{"192.168.1.10", "192.168.1.20", true},
		{"10.0.0.5", "172.16.3.4", true},
		{"127.0.0.1", "127.0.0.1", true},
		{"fd12:3456::1", "fd12:3456::2", true},
		{"2001:db8:1:2::10", "2001:db8:1:2::20", true},
		{"2001:db8:1:2::10", "2001:db8:9:9::20", false},
		{"192.168.1.10", "8.8.8.8", false},
		{"8.8.8.8", "1.1.1.1", false},
		{"100.64.0.1", "100.64.0.2", false},
		{"fe80::1", "fe80::2", false},
		{"fe80::1", "2001:db8:1:2::20", false},
		{"192.168.1.10", "fd12:3456::2", false},
	} {
		if got := sameLAN(netip.MustParseAddr(c.a), netip.MustParseAddr(c.b)); got != c.want {
			t.Errorf("sameLAN(%s, %s) = %v, want %v", c.a, c.b, got, c.want)
		}
	}
}
