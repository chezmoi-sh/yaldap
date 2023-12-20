package utils

import (
	"bytes"
	"log/slog"
	"testing"
	"time"

	"github.com/hashicorp/go-hclog"
	"github.com/stretchr/testify/suite"
)

type HashicorpLoggerWrapperTestSuite struct {
	suite.Suite

	logger *slog.Logger
	buffer *bytes.Buffer
}

func (suite *HashicorpLoggerWrapperTestSuite) SetupTest() {
	suite.buffer = bytes.NewBuffer(nil)
	suite.logger = slog.New(
		slog.NewTextHandler(suite.buffer, &slog.HandlerOptions{
			Level: slog.LevelDebug,
			ReplaceAttr: func(_ []string, attr slog.Attr) slog.Attr {
				switch attr.Key {
				case "time":
					return slog.Attr{Key: "time", Value: slog.TimeValue(time.Time{})}
				default:
					return attr
				}
			},
		}),
	)
}

func (suite *HashicorpLoggerWrapperTestSuite) TestLog() {
	var logger hclog.Logger = &HashicorpLoggerWrapper{Logger: suite.logger}

	tests := []struct {
		level    hclog.Level
		msg      string
		args     []interface{}
		expected string
	}{
		{
			level:    hclog.Trace,
			msg:      "test",
			args:     []interface{}{"key", "value"},
			expected: "time=0001-01-01T00:00:00.000Z level=DEBUG msg=test key=value\n",
		},
		{
			level:    hclog.Debug,
			msg:      "test",
			args:     []interface{}{"key", "value"},
			expected: "time=0001-01-01T00:00:00.000Z level=DEBUG msg=test key=value\n",
		},
		{
			level:    hclog.Info,
			msg:      "test",
			args:     []interface{}{"key", "value"},
			expected: "time=0001-01-01T00:00:00.000Z level=INFO msg=test key=value\n",
		},
		{
			level:    hclog.NoLevel,
			msg:      "test",
			args:     []interface{}{"key", "value"},
			expected: "time=0001-01-01T00:00:00.000Z level=INFO msg=test key=value\n",
		},
		{
			level:    hclog.Warn,
			msg:      "test",
			args:     []interface{}{"key", "value"},
			expected: "time=0001-01-01T00:00:00.000Z level=WARN msg=test key=value\n",
		},
		{
			level:    hclog.Error,
			msg:      "test",
			args:     []interface{}{"key", "value"},
			expected: "time=0001-01-01T00:00:00.000Z level=ERROR msg=test key=value\n",
		},
		{
			level:    hclog.Off,
			msg:      "test",
			args:     []interface{}{"key", "value"},
			expected: "",
		},
	}

	for _, test := range tests {
		suite.T().Run(test.level.String(), func(t *testing.T) {
			logger.Log(test.level, test.msg, test.args...)
			suite.Equal(test.expected, suite.buffer.String())
			suite.buffer.Reset()
		})
	}
}

func (suite *HashicorpLoggerWrapperTestSuite) Test_LogWithLevelLimitation() {
	var logger hclog.Logger = &HashicorpLoggerWrapper{
		Logger: slog.New(slog.NewTextHandler(suite.buffer, &slog.HandlerOptions{Level: slog.LevelWarn})),
	}

	logger.Log(hclog.Debug, "test", "key", "value")
	suite.Empty(suite.buffer.String())
	suite.buffer.Reset()

	logger.Log(hclog.Info, "test", "key", "value")
	suite.Empty(suite.buffer.String())
	suite.buffer.Reset()

	logger.Log(hclog.Warn, "test", "key", "value")
	suite.NotEmpty(suite.buffer.String())
}

func (suite *HashicorpLoggerWrapperTestSuite) TestX() {
	var logger hclog.Logger = &HashicorpLoggerWrapper{Logger: suite.logger}

	tests := []struct {
		name     string
		logFn    func(string, ...interface{})
		expected string
	}{
		{
			name:     "(*HashicorpLoggerWrapper).Trace",
			logFn:    logger.Trace,
			expected: "time=0001-01-01T00:00:00.000Z level=DEBUG msg=test key=value\n",
		},
		{
			name:     "(*HashicorpLoggerWrapper).Debug",
			logFn:    logger.Debug,
			expected: "time=0001-01-01T00:00:00.000Z level=DEBUG msg=test key=value\n",
		},
		{
			name:     "(*HashicorpLoggerWrapper).Info",
			logFn:    logger.Info,
			expected: "time=0001-01-01T00:00:00.000Z level=INFO msg=test key=value\n",
		},
		{
			name:     "(*HashicorpLoggerWrapper).Warn",
			logFn:    logger.Warn,
			expected: "time=0001-01-01T00:00:00.000Z level=WARN msg=test key=value\n",
		},
		{
			name:     "(*HashicorpLoggerWrapper).Error",
			logFn:    logger.Error,
			expected: "time=0001-01-01T00:00:00.000Z level=ERROR msg=test key=value\n",
		},
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			test.logFn("test", "key", "value")
			suite.Equal(test.expected, suite.buffer.String())
			suite.buffer.Reset()
		})
	}
}

func (suite *HashicorpLoggerWrapperTestSuite) TestIsX() {
	var logger hclog.Logger = &HashicorpLoggerWrapper{
		Logger: slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{
			Level: slog.LevelDebug,
		})),
	}

	suite.True(logger.IsTrace())
	suite.True(logger.IsDebug())
	suite.True(logger.IsInfo())
	suite.True(logger.IsWarn())
	suite.True(logger.IsError())

	logger = HashicorpLoggerWrapper{
		Logger: slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{
			Level: slog.LevelWarn,
		})),
	}

	suite.False(logger.IsTrace())
	suite.False(logger.IsDebug())
	suite.False(logger.IsInfo())
	suite.True(logger.IsWarn())
	suite.True(logger.IsError())

	logger = HashicorpLoggerWrapper{
		Logger: slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{
			Level: slog.LevelError + 1,
		})),
	}

	suite.False(logger.IsTrace())
	suite.False(logger.IsDebug())
	suite.False(logger.IsInfo())
	suite.False(logger.IsWarn())
	suite.False(logger.IsError())
}

func (suite *HashicorpLoggerWrapperTestSuite) TestWith() {
	var logger hclog.Logger = &HashicorpLoggerWrapper{Logger: suite.logger}

	logger = logger.With("key", "value")
	logger.Info("test")
	suite.Equal("time=0001-01-01T00:00:00.000Z level=INFO msg=test key=value\n", suite.buffer.String())
}

func (suite *HashicorpLoggerWrapperTestSuite) TestImpliedArgs() {
	var logger hclog.Logger = &HashicorpLoggerWrapper{Logger: suite.logger}

	logger = logger.With("key", "value")
	suite.Equal([]interface{}{"key", "value"}, logger.ImpliedArgs())
}

func (suite *HashicorpLoggerWrapperTestSuite) TestNamed_NoOp() {
	var logger hclog.Logger = &HashicorpLoggerWrapper{Logger: suite.logger}

	suite.Exactly(logger, logger.Named(""))
}

func (suite *HashicorpLoggerWrapperTestSuite) TestResetNamed_NoOp() {
	var logger hclog.Logger = &HashicorpLoggerWrapper{Logger: suite.logger}

	suite.Exactly(logger, logger.ResetNamed(""))
}

func (suite *HashicorpLoggerWrapperTestSuite) TestName() {
	var logger hclog.Logger = &HashicorpLoggerWrapper{Logger: suite.logger}

	suite.Equal("", logger.Name())

	// NOTE: Named and ResetNamed are no-ops.
	logger = logger.Named("test")
	suite.Equal("", logger.Name())
}

func (suite *HashicorpLoggerWrapperTestSuite) TestSetLevel_NoOp() {
	var logger hclog.Logger = &HashicorpLoggerWrapper{Logger: suite.logger}

	logger.Debug("test")
	suite.Equal("time=0001-01-01T00:00:00.000Z level=DEBUG msg=test\n", suite.buffer.String())
	suite.buffer.Reset()

	logger.SetLevel(hclog.Warn)
	logger.Debug("test")
	suite.Equal("time=0001-01-01T00:00:00.000Z level=DEBUG msg=test\n", suite.buffer.String())
}

func (suite *HashicorpLoggerWrapperTestSuite) TestGetLevel() {
	tests := []struct {
		name     string
		logger   *slog.Logger
		expected hclog.Level
	}{
		{
			name:     "slog.LevelDebug",
			logger:   slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelDebug})),
			expected: hclog.Debug,
		},
		{
			name:     "slog.LevelInfo",
			logger:   slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelInfo})),
			expected: hclog.Info,
		},
		{
			name:     "slog.LevelWarn",
			logger:   slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelWarn})),
			expected: hclog.Warn,
		},
		{
			name:     "slog.LevelError",
			logger:   slog.New(slog.NewTextHandler(nil, &slog.HandlerOptions{Level: slog.LevelError})),
			expected: hclog.Error,
		},
	}

	for _, test := range tests {
		suite.Run(test.name, func() {
			var logger hclog.Logger = &HashicorpLoggerWrapper{Logger: test.logger}

			suite.Equal(test.expected, logger.GetLevel())
		})
	}
}

func (suite *HashicorpLoggerWrapperTestSuite) TestStandardLogger() {
	var logger hclog.Logger = &HashicorpLoggerWrapper{Logger: suite.logger}

	suite.PanicsWithValue(
		"not implemented",
		func() { logger.StandardLogger(nil) },
	)
}

func (suite *HashicorpLoggerWrapperTestSuite) TestStandardWriter() {
	var logger hclog.Logger = &HashicorpLoggerWrapper{Logger: suite.logger}

	suite.PanicsWithValue(
		"not implemented",
		func() { logger.StandardWriter(nil) },
	)
}

func TestHashicorpLoggerWrapper(t *testing.T) {
	suite.Run(t, new(HashicorpLoggerWrapperTestSuite))
}
