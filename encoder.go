// Copyright (c) 2017 Timon Wong
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
	"fmt"
	"os"
	"path"
	"sort"
	"strconv"
	"strings"

	"github.com/richiefi/zap-syslog/internal"
	"github.com/richiefi/zap-syslog/internal/bufferpool"
	"github.com/richiefi/zap-syslog/syslog"
	"go.uber.org/zap/buffer"
	"go.uber.org/zap/zapcore"
)

const (
	version         = 1
	severityMask    = 0x07
	facilityMask    = 0xf8
	nilValue        = "-"
	timestampFormat = "2006-01-02T15:04:05.000000Z07:00" // RFC3339 with micro fraction seconds
	maxHostnameLen  = 255
	maxAppNameLen   = 48
)

var (
	_ zapcore.Encoder = &syslogEncoder{}
)

// Framing.
const (
	NonTransparentFraming Framing = iota
	OctetCountingFraming
	DefaultFraming = NonTransparentFraming
)

// Framing configures RFC6587 TCP transport framing.
type Framing int

// SyslogEncoderConfig allows users to configure the concrete encoders for zap syslog.
type SyslogEncoderConfig struct {
	zapcore.EncoderConfig

	Framing      Framing         `json:"framing" yaml:"framing"`
	Facility     syslog.Priority `json:"facility" yaml:"facility"`
	Hostname     string          `json:"hostname" yaml:"hostname"`
	PID          int             `json:"pid" yaml:"pid"`
	App          string          `json:"app" yaml:"app"`
	EnterpriseID int             `json:"enterprise_id" yaml:"enterprise_id"`
}

// syslogEncoder keeps the fields of With in its MapObjectEncoder, and writes
// them with each entry's own fields as its structured data.
type syslogEncoder struct {
	*SyslogEncoderConfig
	*zapcore.MapObjectEncoder
}

func rfc5424CompliantASCIIMapper(r rune) rune {
	// PRINTUSASCII    = %d33-126
	if r < 33 || r > 126 {
		return '_'
	}
	return r
}

func toRFC5424CompliantASCIIString(s string) string {
	return strings.Map(rfc5424CompliantASCIIMapper, s)
}

// NewSyslogEncoder creates a syslogEncoder.
func NewSyslogEncoder(cfg SyslogEncoderConfig) zapcore.Encoder {
	if cfg.Hostname == "" {
		hostname, _ := os.Hostname()
		cfg.Hostname = hostname
	}
	if cfg.Hostname == "" {
		cfg.Hostname = nilValue
	} else {
		hostname := toRFC5424CompliantASCIIString(cfg.Hostname)
		if len(hostname) > maxHostnameLen {
			hostname = hostname[:maxHostnameLen]
		}
		cfg.Hostname = hostname
	}

	if cfg.PID == 0 {
		cfg.PID = os.Getpid()
	}
	if cfg.App == "" {
		cfg.App = nilValue
	} else {
		app := cfg.App
		if len(app) > maxAppNameLen {
			app = path.Base(app)
		}
		if len(app) > maxAppNameLen {
			app = app[:maxAppNameLen]
		}
		app = toRFC5424CompliantASCIIString(app)
	}

	return &syslogEncoder{
		SyslogEncoderConfig: &cfg,
		MapObjectEncoder:    zapcore.NewMapObjectEncoder(),
	}
}

func (enc *syslogEncoder) Clone() zapcore.Encoder {
	return enc.clone()
}

func (enc *syslogEncoder) clone() *syslogEncoder {
	clone := &syslogEncoder{
		SyslogEncoderConfig: enc.SyslogEncoderConfig,
		MapObjectEncoder:    zapcore.NewMapObjectEncoder(),
	}
	for k, v := range enc.Fields {
		clone.Fields[k] = v
	}
	return clone
}

func (enc *syslogEncoder) EncodeEntry(ent zapcore.Entry, fields []zapcore.Field) (*buffer.Buffer, error) {
	msg := bufferpool.Get()

	var p syslog.Priority
	switch ent.Level {
	case zapcore.FatalLevel:
		p = syslog.LOG_EMERG
	case zapcore.PanicLevel:
		p = syslog.LOG_CRIT
	case zapcore.DPanicLevel:
		p = syslog.LOG_CRIT
	case zapcore.ErrorLevel:
		p = syslog.LOG_ERR
	case zapcore.WarnLevel:
		p = syslog.LOG_WARNING
	case zapcore.InfoLevel:
		p = syslog.LOG_INFO
	case zapcore.DebugLevel:
		p = syslog.LOG_DEBUG
	}
	pr := int64((enc.Facility & facilityMask) | (p & severityMask))

	// <PRI>version
	msg.AppendByte('<')
	msg.AppendInt(pr)
	msg.AppendByte('>')
	msg.AppendInt(version)

	// SP TIMESTAMP
	msg.AppendByte(' ')
	if ent.Time.IsZero() {
		msg.AppendString(nilValue)
	} else {
		msg.AppendString(ent.Time.Format(timestampFormat))
	}

	// SP HOSTNAME
	msg.AppendByte(' ')
	msg.AppendString(enc.Hostname)

	// SP APP-NAME
	msg.AppendByte(' ')
	msg.AppendString(enc.App)

	// SP PROCID
	msg.AppendByte(' ')
	msg.AppendInt(int64(enc.PID))

	// SP MSGID
	msg.AppendByte(' ')
	if ent.Caller.Defined {
		msg.AppendString(ent.Caller.FullPath())
	} else {
		msg.AppendString(nilValue)
	}

	// SP STRUCTURED-DATA
	msg.AppendByte(' ')
	msg.AppendString(enc.encodeStructuredData(fields))

	// SP UTF8 MSG
	if len(ent.Message) > 0 {
		msg.AppendString(" \xef\xbb\xbf")
		msg.AppendString(ent.Message)
	}

	if enc.Framing != OctetCountingFraming {
		return msg, nil
	}

	// SYSLOG-FRAME = MSG-LEN SP SYSLOG-MSG
	out := bufferpool.Get()
	out.AppendInt(int64(msg.Len()))
	out.AppendByte(' ')
	out.AppendString(internal.BytesToString(msg.Bytes()))
	msg.Free()
	return out, nil
}

func (enc *syslogEncoder) encodeStructuredData(fields []zapcore.Field) string {
	all := enc.clone()
	for _, f := range fields {
		f.AddTo(all)
	}
	if len(all.Fields) == 0 {
		return nilValue
	}
	keys := make([]string, 0, len(all.Fields))
	for k := range all.Fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var buf buffer.Buffer
	buf.AppendString("[" + enc.App + "@" + strconv.Itoa(enc.EnterpriseID))
	for _, k := range keys {
		buf.AppendByte(' ')
		buf.AppendString(sdName(k))
		buf.AppendString(`="`)
		buf.AppendString(sdParamValueEscaper.Replace(fmt.Sprint(all.Fields[k])))
		buf.AppendByte('"')
	}
	buf.AppendByte(']')
	return buf.String()
}

// sdParamValueEscaper escapes what RFC 5424 requires in a PARAM-VALUE.
var sdParamValueEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, `]`, `\]`)

// sdName is k as an RFC 5424 SD-NAME: up to 32 printable ASCII characters
// other than '=', ' ', ']' and '"'.
func sdName(k string) string {
	n := strings.Map(func(r rune) rune {
		if r == '=' || r == ']' || r == '"' {
			return '_'
		}
		return rfc5424CompliantASCIIMapper(r)
	}, k)
	if len(n) > 32 {
		n = n[:32]
	}
	return n
}
