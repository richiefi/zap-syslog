// Modifications Copyright (c) 2017 Timon Wong
// Copyright (c) 2016 Uber Technologies, Inc.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

package zapsyslog

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/richiefi/zap-syslog/syslog"
	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

var (
	testEntry = zapcore.Entry{
		Time:    time.Date(2017, 1, 2, 3, 4, 5, 123456789, time.UTC),
		Message: "fake",
		Level:   zap.DebugLevel,
	}
)

func TestToRFC5424CompliantASCIIString(t *testing.T) {
	fixtures := []struct {
		s        string
		expected string
	}{
		{
			s:        " abc ",
			expected: "_abc_",
		},
		{
			s:        "中文",
			expected: "__",
		},
		{
			s:        "\x00\x01\x02\x03\x04test",
			expected: "_____test",
		},
	}

	for _, f := range fixtures {
		actual := toRFC5424CompliantASCIIString(f.s)
		require.Equal(t, f.expected, actual)
	}
}

// Nested Array- and ObjectMarshalers.
type turducken struct{}

func (t turducken) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	return enc.AddArray("ducks", zapcore.ArrayMarshalerFunc(func(arr zapcore.ArrayEncoder) error {
		for i := 0; i < 2; i++ {
			arr.AppendObject(zapcore.ObjectMarshalerFunc(func(inner zapcore.ObjectEncoder) error {
				inner.AddString("in", "chicken")
				return nil
			}))
		}
		return nil
	}))
}

type turduckens int

func (t turduckens) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	var err error
	tur := turducken{}
	for i := 0; i < int(t); i++ {
		err = multierr.Append(err, enc.AppendObject(tur))
	}
	return err
}

type loggable struct{ bool }

func (l loggable) MarshalLogObject(enc zapcore.ObjectEncoder) error {
	if !l.bool {
		return errors.New("can't marshal")
	}
	enc.AddString("loggable", "yes")
	return nil
}

func (l loggable) MarshalLogArray(enc zapcore.ArrayEncoder) error {
	if !l.bool {
		return errors.New("can't marshal")
	}
	enc.AppendBool(true)
	return nil
}

type noJSON struct{}

func (nj noJSON) MarshalJSON() ([]byte, error) {
	return nil, errors.New("no")
}

func testEncoderConfig(framing Framing) SyslogEncoderConfig {
	return SyslogEncoderConfig{
		EncoderConfig: zapcore.EncoderConfig{
			MessageKey:     "msg",
			NameKey:        "name",
			CallerKey:      "caller",
			StacktraceKey:  "stacktrace",
			EncodeTime:     zapcore.EpochTimeEncoder,
			EncodeLevel:    zapcore.LowercaseLevelEncoder,
			EncodeDuration: zapcore.SecondsDurationEncoder,
			EncodeCaller:   zapcore.ShortCallerEncoder,
		},

		Framing:      framing,
		Hostname:     "localhost",
		App:          "encoder_test",
		EnterpriseID: 112,
		PID:          9876,
		Facility:     syslog.LOG_LOCAL0,
	}
}

func testSyslogEncoderFraming(t *testing.T, framing Framing) {
	enc := NewSyslogEncoder(testEncoderConfig(framing))
	enc.AddString("str", "foo")
	enc.AddInt64("int64-1", 1)
	enc.AddInt64("int64-2", 2)
	enc.AddFloat64("float64", 1.0)
	enc.AddString("string1", "\n")
	enc.AddString("string2", "💩")
	enc.AddString("string3", "🤔")
	enc.AddString("string4", "🙊")
	enc.AddBool("bool", true)
	buf, _ := enc.EncodeEntry(testEntry, nil)
	defer buf.Free()

	msg := buf.String()
	msgPrefix := "<135>1 2017-01-02T03:04:05.123456Z localhost encoder_test 9876 - - \xef\xbb\xbf"
	if framing == OctetCountingFraming {
		spacePos := strings.Index(msg, " ") + 1
		msgPrefix = fmt.Sprintf("%d %s", buf.Len()-spacePos, msgPrefix)
	}

	if !strings.HasPrefix(msg, msgPrefix) {
		t.Errorf("Wrong syslog output for framing: %d", framing)
		t.Log(msg)
		t.Log(msgPrefix)
		return
	}

	if framing == OctetCountingFraming && strings.HasSuffix(msg, "\n") {
		t.Errorf("syslog output for OctetCountingFraming should not ends with `\\n`")
		return
	}
}

func TestSyslogEncoderStructuredData(t *testing.T) {
	enc := NewSyslogEncoder(testEncoderConfig(NonTransparentFraming))
	enc.AddString("str", "foo")
	enc.AddInt64("int64-1", 1)
	enc.AddInt64("int64-2", 2)
	enc.AddFloat64("float64", 1.0)
	enc.AddString("string1", "\n")
	enc.AddString("string2", "💩")
	enc.AddString("string3", "🤔")
	enc.AddString("string4", "🙊")
	enc.AddBool("bool", true)

	// Add fields to encode into structured data
	buf, _ := enc.EncodeEntry(testEntry, []zapcore.Field{zap.String("a-str", "pebcak"), zap.Int64("i64", 42), zap.Uint32("u32", 314), zap.Float64("f64", 3.14), zap.Bool("b", true), zap.Error(errors.New("boom"))})
	defer buf.Free()
	msg := buf.String()
	msgPrefix := "<135>1 2017-01-02T03:04:05.123456Z localhost encoder_test 9876 - [encoder_test@112 a-str=\"pebcak\" i64=\"42\" u32=\"314\" f64=\"3.14\" b=\"true\" error=\"boom\"] \xef\xbb\xbf"
	if !strings.HasPrefix(msg, msgPrefix) {
		t.Errorf("Wrong syslog output for structured data")
		t.Log(msg)
		t.Log(msgPrefix)
		return
	}
}

func TestSyslogEncoder(t *testing.T) {
	for _, framing := range []Framing{NonTransparentFraming, OctetCountingFraming} {
		testSyslogEncoderFraming(t, framing)
	}
}
