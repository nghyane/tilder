package identity

import (
	"errors"
	"strconv"
	"strings"
	"time"
)

// DeviceRegistration is a device's word that a machine key is one of the
// owner's machines (ADR 0053): signed by the device key, which signs only
// for a machine that proved its key with a join command this browser made.
// It counts only together with the device's certificate from the root, and
// only while that certificate is valid and the device not removed; the root
// signs the machine again when it is next opened to renew one.
type DeviceRegistration struct {
	Root    RootPublic
	Device  DevicePublic
	Machine MachinePublic
	At      time.Time
}

// ErrDeviceRegistration covers every way a device's registration fails to
// check out against its certificate.
var ErrDeviceRegistration = errors.New("identity: device registration is invalid")

// Statement is what the device signs.
func (r DeviceRegistration) Statement() DeviceStatement {
	return DeviceStatement{statement("register-by-device",
		[2]string{"user", UserID(r.Root)},
		[2]string{"machine", MachineID(r.Machine)},
		[2]string{"machine_pub", b64(r.Machine.k[:])},
		[2]string{"device", b64(r.Device.k[:])},
		[2]string{"at", strconv.FormatInt(r.At.Unix(), 10)})}
}

// VerifyDeviceRegistration checks a device's registration off the wire
// against cert, which the caller has verified (VerifyDeviceCert) and found
// not removed: exactly the canonical text, for cert's user and device,
// signed by that device, at a time inside cert's validity and not after now
// + ClockSkew. The machine id is re-derived from the key it names.
func VerifyDeviceRegistration(text string, sig []byte, cert DeviceCert, now time.Time) (DeviceRegistration, error) {
	if len(text) > maxCertText || !strings.HasSuffix(text, "\n") {
		return DeviceRegistration{}, ErrDeviceRegistration
	}
	lines := strings.Split(strings.TrimSuffix(text, "\n"), "\n")
	keys := []string{"user", "machine", "machine_pub", "device", "at"}
	if len(lines) != len(keys)+1 || lines[0] != "tilder/register-by-device/v2" {
		return DeviceRegistration{}, ErrDeviceRegistration
	}
	v := make(map[string]string, len(keys))
	for i, key := range keys {
		k, val, ok := strings.Cut(lines[i+1], "=")
		if !ok || k != key {
			return DeviceRegistration{}, ErrDeviceRegistration
		}
		v[key] = val
	}
	raw, err := fromB64(v["machine_pub"])
	if err != nil {
		return DeviceRegistration{}, ErrDeviceRegistration
	}
	machine, err := MachinePublicFromBytes(raw)
	if err != nil {
		return DeviceRegistration{}, ErrDeviceRegistration
	}
	at, err := strconv.ParseInt(v["at"], 10, 64)
	if err != nil {
		return DeviceRegistration{}, ErrDeviceRegistration
	}
	r := DeviceRegistration{Root: cert.Root, Device: cert.Device, Machine: machine, At: time.Unix(at, 0)}
	// The canonical text names the cert's user and device, so a text for
	// another device or user cannot pass; and only that device signed it.
	if r.Statement().Text() != text || !cert.Device.Verify(DeviceStatement{text: []byte(text)}, sig) ||
		r.At.After(now.Add(ClockSkew)) ||
		r.At.Before(cert.NotBefore.Add(-ClockSkew)) || r.At.After(cert.NotAfter.Add(ClockSkew)) {
		return DeviceRegistration{}, ErrDeviceRegistration
	}
	return r, nil
}
