package cmd

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/alecthomas/kong"
)

type (
	Base struct {
		Log struct {
			Format string   `name:"format" enum:"text,json" help:"Log format" default:"json"`
			Level  LogLevel `name:"level" help:"Log level" default:"info"`
		} `embed:"" prefix:"log."`
	}
	LogLevel slog.Level
)

func (b Base) Logger() *slog.Logger {
	opts := &slog.HandlerOptions{
		AddSource: slog.Level(b.Log.Level) == slog.LevelDebug,
		Level:     slog.Level(b.Log.Level),
	}

	switch b.Log.Format {
	case "text":
		return slog.New(slog.NewTextHandler(os.Stderr, opts))
	case "json":
		return slog.New(slog.NewJSONHandler(os.Stderr, opts))
	case "test": //nolint:goconst
		// This logger is used for testing only and will never be available in the CLI.
		return slog.New(slog.NewTextHandler(io.Discard, opts))
	default:
		return slog.Default()
	}
}

func (l *LogLevel) Decode(ctx *kong.DecodeContext) error {
	var level string

	err := ctx.Scan.PopValueInto("level", &level)
	if err != nil {
		return err
	}

	switch level {
	case "debug":
		*l = LogLevel(slog.LevelDebug)
	case "info":
		*l = LogLevel(slog.LevelInfo)
	case "warn":
		*l = LogLevel(slog.LevelWarn)
	case "error":
		*l = LogLevel(slog.LevelError)
	default:
		return fmt.Errorf("invalid level '%s': only debug, info, warn and error are allowed", level)
	}
	return nil
}
