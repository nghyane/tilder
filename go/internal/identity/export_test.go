package identity

// DeviceStatementForTest wraps any text as a device statement, so tests can
// sign a malformed one; it exists only in test builds.
func DeviceStatementForTest(text string) DeviceStatement { return DeviceStatement{text: []byte(text)} }

// OwnerStatementForTest wraps any text as an owner statement, so tests can
// have the root sign a malformed one; it exists only in test builds.
func OwnerStatementForTest(text string) OwnerStatement { return OwnerStatement{text: []byte(text)} }
