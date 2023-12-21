package utils

import (
	"bytes"
	"context"
	"io"
	"log"
	"log/slog"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/hashicorp/go-hclog"
)

type (
	HashicorpLoggerWrapper struct {
		Logger *slog.Logger

		args []interface{}
	}
	HashicorpLoggerWriter struct {
		logger *slog.Logger
		level  slog.Level
		buffer *bytes.Buffer
		last   time.Time

		rwm sync.RWMutex
	}
)

const (
	// TraceLevel designates finer-grained informational events than the Debug.
	LevelTrace = slog.LevelDebug * 2
)

var (
	hclogLevels = map[hclog.Level]slog.Level{
		hclog.Trace:   LevelTrace,
		hclog.Debug:   slog.LevelDebug,
		hclog.Info:    slog.LevelInfo,
		hclog.NoLevel: slog.LevelInfo,
		hclog.Warn:    slog.LevelWarn,
		hclog.Error:   slog.LevelError,
	}
	slogLevels = map[slog.Level]hclog.Level{
		LevelTrace:      hclog.Trace,
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
	logger.log(LevelTrace, msg, args...)
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
	return logger.Logger.Enabled(context.TODO(), LevelTrace)
}

// Indicate if DEBUG logs would be emitted. This and the other Is* guards.
func (logger HashicorpLoggerWrapper) IsDebug() bool {
	return logger.Logger.Enabled(context.TODO(), slog.LevelDebug)
}

// Indicate if INFO logs would be emitted. This and the other Is* guards.
func (logger HashicorpLoggerWrapper) IsInfo() bool {
	return logger.Logger.Enabled(context.Background(), slog.LevelInfo)
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
	for _, level := range []slog.Level{LevelTrace, slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		if logger.Logger.Enabled(context.Background(), level) {
			return level
		}
	}
	return slog.LevelInfo
}

// Return a value that conforms to the stdlib log.Logger interface.
func (logger HashicorpLoggerWrapper) StandardLogger(opts *hclog.StandardLoggerOptions) *log.Logger {
	level := logger.getLevel()
	if opts != nil {
		level = hclogLevels[opts.ForceLevel]
	}

	return slog.NewLogLogger(logger.Logger.Handler(), level)
}

// Return a value that conforms to io.Writer, which can be passed into log.SetOutput().
// NOTE: this is only used by gldap package to pretty print LDAP packets. For this
// purpose, we will log messages only if the current level is lower than Trace.
func (logger HashicorpLoggerWrapper) StandardWriter(*hclog.StandardLoggerOptions) io.Writer {
	writer := &HashicorpLoggerWriter{
		logger: logger.Logger,
		level:  LevelTrace,
		buffer: bytes.NewBuffer(nil),
		last:   time.Now(),
	}
	go writer.flushPeriodically()
	return writer
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
	_ = logger.Logger.Handler().Handle(context.Background(), record)
}

// Write implements io.Writer.
func (writer *HashicorpLoggerWriter) Write(p []byte) (n int, err error) {
	writer.rwm.Lock()
	defer writer.rwm.Unlock()

	if !writer.logger.Enabled(context.Background(), writer.level) {
		return 0, nil
	}

	writer.last = time.Now()
	return writer.buffer.Write(p)
}

func (writer *HashicorpLoggerWriter) flushPeriodically() {
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()

	for range ticker.C {
		writer.rwm.RLock()

		if time.Since(writer.last) > 10*time.Millisecond && writer.buffer.Len() > 0 {
			var pcs [1]uintptr
			runtime.Callers(0, pcs[:])

			record := slog.NewRecord(
				time.Now(),
				writer.level,
				strings.TrimSuffix(writer.buffer.String(), "\n"),
				pcs[0],
			)
			_ = writer.logger.Handler().Handle(context.Background(), record)
			writer.buffer.Reset()
		}
		writer.rwm.RUnlock()
	}
}
