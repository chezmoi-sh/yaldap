package cmd_test

import (
	"log/slog"
	"os"
	"testing"

	"github.com/alecthomas/kong"
	"github.com/stretchr/testify/assert"
	"github.com/xunleii/yaldap/pkg/cmd"
	"github.com/xunleii/yaldap/pkg/utils"
)

func TestLogger_Format(t *testing.T) {
	format := []string{"json", "text"}

	for _, f := range format {
		t.Run(f, func(t *testing.T) {
			os.Args = []string{"...", "--log.format", f}

			var base cmd.Base
			kong.Parse(&base)
			assert.Equal(t, f, base.Log.Format)
		})
	}
}

func TestLogger_Level(t *testing.T) {
	levels := map[string]slog.Level{
		"trace": utils.LevelTrace,
		"debug": slog.LevelDebug,
		"info":  slog.LevelInfo,
		"warn":  slog.LevelWarn,
		"error": slog.LevelError,
	}

	for l, s := range levels {
		t.Run(l, func(t *testing.T) {
			os.Args = []string{"...", "--log.level", l}

			var base cmd.Base
			kong.Parse(&base)
			assert.Equal(t, cmd.LogLevel(s), base.Log.Level)
		})
	}
}
