//go:build !windows && !linux

package intercept

import (
	"github.com/DestroyersTaken/SentinelProxy/internal/config"
	"github.com/DestroyersTaken/SentinelProxy/internal/engine"
)

func start(*engine.Engine, config.Settings) (Interceptor, error) { return nil, ErrUnsupported }

func available() (bool, string) { return false, ErrUnsupported.Error() }
