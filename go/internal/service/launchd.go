package service

import (
	"bytes"
	"encoding/xml"
	"regexp"
	"strings"
)

// LaunchdPlist is the LaunchAgent. AbandonProcessGroup is the point: launchd
// kills a job's process group when it exits, and keeps nothing it did not
// start alive otherwise.
func LaunchdPlist(s Spec) string {
	var b strings.Builder
	b.WriteString(`<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
` + plistMarker + `
<plist version="1.0">
<dict>
`)
	key := func(k, v string) { b.WriteString("\t<key>" + k + "</key>\n\t<string>" + xmlText(v) + "</string>\n") }
	flag := func(k string) { b.WriteString("\t<key>" + k + "</key>\n\t<true/>\n") }
	key("Label", s.Label())
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n\t\t<string>" + xmlText(s.Binary) + "</string>\n\t</array>\n")
	b.WriteString("\t<key>EnvironmentVariables</key>\n\t<dict>\n")
	for _, k := range s.envKeys() {
		b.WriteString("\t\t<key>" + xmlText(k) + "</key>\n\t\t<string>" + xmlText(s.Env[k]) + "</string>\n")
	}
	b.WriteString("\t</dict>\n")
	flag("RunAtLoad")
	flag("KeepAlive")
	flag("AbandonProcessGroup")
	key("ProcessType", "Interactive")
	b.WriteString("\t<key>ThrottleInterval</key>\n\t<integer>5</integer>\n")
	key("StandardOutPath", s.LogPath())
	key("StandardErrorPath", s.LogPath())
	b.WriteString("</dict>\n</plist>\n")
	return b.String()
}

func xmlText(v string) string {
	var b bytes.Buffer
	_ = xml.EscapeText(&b, []byte(v))
	return b.String()
}

var launchdPid = regexp.MustCompile(`(?m)^\s*pid = (\d+)`)

func launchdState(print string) string {
	state := "loaded"
	for line := range strings.Lines(print) {
		if t := strings.TrimSpace(line); strings.HasPrefix(t, "state = ") {
			state = strings.TrimPrefix(t, "state = ")
			break
		}
	}
	if m := launchdPid.FindStringSubmatch(print); m != nil {
		state += " (pid " + m[1] + ")"
	}
	return state
}
