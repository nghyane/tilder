package service_test

import (
	"testing"

	"go.uber.org/goleak"

	"github.com/nghyane/tilder/go/internal/testutil"
)

func TestMain(m *testing.M) { goleak.VerifyTestMain(m, testutil.GoleakOptions...) }
