package identity

// DeviceStatementForTest wraps any text as a device statement, so tests can
// sign a malformed one; it exists only in test builds.
func DeviceStatementForTest(text string) DeviceStatement { return DeviceStatement{text: []byte(text)} }
