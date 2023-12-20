package utils

import (
	"context"
	"io"
	"log"
	"log/slog"
	"runtime"
	"time"

	"github.com/hashicorp/go-hclog"
)

type (
	HashicorpLoggerWrapper struct {
		*slog.Logger

		args []interface{}
	}
)

var (
	hclogLevels = map[hclog.Level]slog.Level{
		hclog.Trace:   slog.LevelDebug,
		hclog.Debug:   slog.LevelDebug,
		hclog.Info:    slog.LevelInfo,
		hclog.NoLevel: slog.LevelInfo,
		hclog.Warn:    slog.LevelWarn,
		hclog.Error:   slog.LevelError,
	}
	slogLevels = map[slog.Level]hclog.Level{
		slog.LevelDebug: hclog.Debug,
		slog.LevelInfo:  hclog.Info,
		slog.LevelWarn:  hclog.Warn,
		slog.LevelError: hclog.Error,
	}
)

// Args are alternating key, val pairs
// keys must be strings
// vals can be any type, but display is implementation specific
// Emit a message and key/value pairs at a provided log level.
func (logger HashicorpLoggerWrapper) Log(level hclog.Level, msg string, args ...interface{}) {
	if level == hclog.Off {
		return
	}
	logger.log(hclogLevels[level], msg, args...)
}

// Emit a message and key/value pairs at the TRACE level.
func (logger HashicorpLoggerWrapper) Trace(msg string, args ...interface{}) {
	logger.log(slog.LevelDebug, msg, args...)
}

// Emit a message and key/value pairs at the DEBUG level.
func (logger HashicorpLoggerWrapper) Debug(msg string, args ...interface{}) {
	logger.log(slog.LevelDebug, msg, args...)
}

// Emit a message and key/value pairs at the INFO level.
func (logger HashicorpLoggerWrapper) Info(msg string, args ...interface{}) {
	logger.log(slog.LevelInfo, msg, args...)
}

// Emit a message and key/value pairs at the WARN level.
func (logger HashicorpLoggerWrapper) Warn(msg string, args ...interface{}) {
	logger.log(slog.LevelWarn, msg, args...)
}

// Emit a message and key/value pairs at the ERROR level.
func (logger HashicorpLoggerWrapper) Error(msg string, args ...interface{}) {
	logger.log(slog.LevelError, msg, args...)
}

// Indicate if TRACE logs would be emitted. This and the other Is* guards
// are used to elide expensive logging code based on the current level.
func (logger HashicorpLoggerWrapper) IsTrace() bool {
	return logger.Logger.Enabled(context.TODO(), slog.LevelDebug)
}

// Indicate if DEBUG logs would be emitted. This and the other Is* guards.
func (logger HashicorpLoggerWrapper) IsDebug() bool {
	return logger.Logger.Enabled(context.TODO(), slog.LevelDebug)
}

// Indicate if INFO logs would be emitted. This and the other Is* guards.
func (logger HashicorpLoggerWrapper) IsInfo() bool {
	return logger.Enabled(context.Background(), slog.LevelInfo)
}

// Indicate if WARN logs would be emitted. This and the other Is* guards.
func (logger HashicorpLoggerWrapper) IsWarn() bool {
	return logger.Logger.Enabled(context.TODO(), slog.LevelWarn)
}

// Indicate if ERROR logs would be emitted. This and the other Is* guards.
func (logger HashicorpLoggerWrapper) IsError() bool {
	return logger.Logger.Enabled(context.Background(), slog.LevelError)
}

// ImpliedArgs returns With key/value pairs.
func (logger HashicorpLoggerWrapper) ImpliedArgs() []interface{} {
	return logger.args
}

// Creates a sublogger that will always have the given key/value pairs.
func (logger HashicorpLoggerWrapper) With(args ...interface{}) hclog.Logger {
	return &HashicorpLoggerWrapper{
		Logger: logger.Logger.With(args...),
		args:   append(logger.args, args...),
	}
}

// Returns the Name of the logger.
func (logger HashicorpLoggerWrapper) Name() string { return "" }

// Create a logger that will prepend the name string on the front of all messages.
// If the logger already has a name, the new value will be appended to the current
// name. That way, a major subsystem can use this to decorate all it's own logs
// without losing context.
func (logger HashicorpLoggerWrapper) Named(string) hclog.Logger {
	return &logger
}

// Create a logger that will prepend the name string on the front of all messages.
// This sets the name of the logger to the value directly, unlike Named which honor
// the current name as well.
func (logger HashicorpLoggerWrapper) ResetNamed(string) hclog.Logger {
	return &logger
}

// Updates the level. This should affect all related loggers as well,
// unless they were created with IndependentLevels. If an
// implementation cannot update the level on the fly, it should no-op.
func (logger HashicorpLoggerWrapper) SetLevel(hclog.Level) {}

// Returns the current level.
func (logger HashicorpLoggerWrapper) GetLevel() hclog.Level {
	return slogLevels[logger.getLevel()]
}

func (logger HashicorpLoggerWrapper) getLevel() slog.Level {
	for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		if logger.Logger.Enabled(context.Background(), level) {
			return level
		}
	}
	return slog.LevelInfo
}

// Return a value that conforms to the stdlib log.Logger interface.
func (logger HashicorpLoggerWrapper) StandardLogger(*hclog.StandardLoggerOptions) *log.Logger {
	panic("not implemented")
}

// Return a value that conforms to io.Writer, which can be passed into log.SetOutput().
func (logger HashicorpLoggerWrapper) StandardWriter(*hclog.StandardLoggerOptions) io.Writer {
	panic("not implemented")
}

func (logger HashicorpLoggerWrapper) log(level slog.Level, msg string, args ...interface{}) {
	if !logger.Logger.Enabled(context.Background(), level) {
		return
	}

	var pcs [1]uintptr
	// skip [runtime.Callers, this function, this function's caller]
	runtime.Callers(3, pcs[:])

	record := slog.NewRecord(time.Now(), level, msg, pcs[0])
	record.Add(args...)
	_ = logger.Handler().Handle(context.Background(), record)
}
