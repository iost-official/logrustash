package logrustash

import (
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/sirupsen/logrus"
)

// Declare the number of logs that can be in progress before logging will start blocking.
const asyncFireBufferSize = 8192

// Hook represents a connection to a Logstash instance
type Hook struct {
	conn             net.Conn
	appName          string
	alwaysSentFields logrus.Fields
	hookOnlyPrefix   string
	TimeFormat       string
	fireChannel      chan *logrus.Entry
	Timeout          time.Duration
}

// NewHook creates a new hook to a Logstash instance, which listens on
// `protocol`://`address`.
func NewHook(protocol, address, appName string) (*Hook, error) {
	return NewHookWithFields(protocol, address, appName, make(logrus.Fields))
}

// NewAsyncHook creates a new hook to a Logstash instance, which listens on
// `protocol`://`address`.
// Logs will be sent asynchronously.
func NewAsyncHook(protocol, address, appName string) (*Hook, error) {
	return NewAsyncHookWithFields(protocol, address, appName, make(logrus.Fields))
}

// NewHookWithConn creates a new hook to a Logstash instance, using the supplied connection.
func NewHookWithConn(conn net.Conn, appName string) (*Hook, error) {
	return NewHookWithFieldsAndConn(conn, appName, make(logrus.Fields))
}

// NewAsyncHookWithConn creates a new hook to a Logstash instance, using the supplied connection.
// Logs will be sent asynchronously.
func NewAsyncHookWithConn(conn net.Conn, appName string) (*Hook, error) {
	return NewAsyncHookWithFieldsAndConn(conn, appName, make(logrus.Fields))
}

// NewHookWithFields creates a new hook to a Logstash instance, which listens on
// `protocol`://`address`. alwaysSentFields will be sent with every log entry.
func NewHookWithFields(protocol, address, appName string, alwaysSentFields logrus.Fields) (*Hook, error) {
	return NewHookWithFieldsAndPrefix(protocol, address, appName, alwaysSentFields, "")
}

// NewAsyncHookWithFields creates a new hook to a Logstash instance, which listens on
// `protocol`://`address`. alwaysSentFields will be sent with every log entry.
// Logs will be sent asynchronously.
func NewAsyncHookWithFields(protocol, address, appName string, alwaysSentFields logrus.Fields) (*Hook, error) {
	return NewAsyncHookWithFieldsAndPrefix(protocol, address, appName, alwaysSentFields, "")
}

// NewHookWithFieldsAndPrefix creates a new hook to a Logstash instance, which listens on
// `protocol`://`address`. alwaysSentFields will be sent with every log entry. prefix is used to select fields to filter.
func NewHookWithFieldsAndPrefix(protocol, address, appName string, alwaysSentFields logrus.Fields, prefix string) (*Hook, error) {
	conn, err := net.Dial(protocol, address)
	if err != nil {
		return nil, err
	}
	return NewHookWithFieldsAndConnAndPrefix(conn, appName, alwaysSentFields, prefix)
}

// NewAsyncHookWithFieldsAndPrefix creates a new hook to a Logstash instance, which listens on
// `protocol`://`address`. alwaysSentFields will be sent with every log entry. prefix is used to select fields to filter.
// Logs will be sent asynchronously.
func NewAsyncHookWithFieldsAndPrefix(protocol, address, appName string, alwaysSentFields logrus.Fields, prefix string) (*Hook, error) {
	hook, err := NewHookWithFieldsAndPrefix(protocol, address, appName, alwaysSentFields, prefix)
	if err != nil {
		return nil, err
	}
	hook.makeAsync()
	return hook, err
}

// NewHookWithFieldsAndConn creates a new hook to a Logstash instance using the supplied connection.
func NewHookWithFieldsAndConn(conn net.Conn, appName string, alwaysSentFields logrus.Fields) (*Hook, error) {
	return NewHookWithFieldsAndConnAndPrefix(conn, appName, alwaysSentFields, "")
}

// NewAsyncHookWithFieldsAndConn creates a new hook to a Logstash instance using the supplied connection.
// Logs will be sent asynchronously.
func NewAsyncHookWithFieldsAndConn(conn net.Conn, appName string, alwaysSentFields logrus.Fields) (*Hook, error) {
	return NewAsyncHookWithFieldsAndConnAndPrefix(conn, appName, alwaysSentFields, "")
}

//NewHookWithFieldsAndConnAndPrefix creates a new hook to a Logstash instance using the suppolied connection and prefix.
func NewHookWithFieldsAndConnAndPrefix(conn net.Conn, appName string, alwaysSentFields logrus.Fields, prefix string) (*Hook, error) {
	return &Hook{conn: conn, appName: appName, alwaysSentFields: alwaysSentFields, hookOnlyPrefix: prefix}, nil
}

// NewAsyncHookWithFieldsAndConnAndPrefix creates a new hook to a Logstash instance using the suppolied connection and prefix.
// Logs will be sent asynchronously.
func NewAsyncHookWithFieldsAndConnAndPrefix(conn net.Conn, appName string, alwaysSentFields logrus.Fields, prefix string) (*Hook, error) {
	hook := &Hook{conn: conn, appName: appName, alwaysSentFields: alwaysSentFields, hookOnlyPrefix: prefix}
	hook.makeAsync()
	return hook, nil
}

// NewFilterHook makes a new hook which does not forward to logstash, but simply enforces the prefix rules.
func NewFilterHook() *Hook {
	return NewFilterHookWithPrefix("")
}

// NewAsyncFilterHook makes a new hook which does not forward to logstash, but simply enforces the prefix rules.
// Logs will be sent asynchronously.
func NewAsyncFilterHook() *Hook {
	return NewAsyncFilterHookWithPrefix("")
}

// NewFilterHookWithPrefix make a new hook which does not forward to logstash, but simply enforces the specified prefix.
func NewFilterHookWithPrefix(prefix string) *Hook {
	return &Hook{conn: nil, appName: "", alwaysSentFields: make(logrus.Fields), hookOnlyPrefix: prefix}
}

// NewAsyncFilterHookWithPrefix make a new hook which does not forward to logstash, but simply enforces the specified prefix.
// Logs will be sent asynchronously.
func NewAsyncFilterHookWithPrefix(prefix string) *Hook {
	hook := NewFilterHookWithPrefix(prefix)
	hook.makeAsync()
	return hook
}

func (h *Hook) makeAsync() {
	h.fireChannel = make(chan *logrus.Entry, asyncFireBufferSize)
	// Set default timeout.
	if h.Timeout == 0 {
		h.Timeout = 100 * time.Millisecond
	}

	go func() {
		for entry := range h.fireChannel {
			h.conn.SetWriteDeadline(time.Now().Add(h.Timeout))
			if err := h.sendMessage(entry); err != nil {
				fmt.Println("Error during sending message to logstash:", err)
			}
		}
	}()
}

func (h *Hook) filterHookOnly(entry *logrus.Entry) {
	if h.hookOnlyPrefix != "" {
		for key := range entry.Data {
			if strings.HasPrefix(key, h.hookOnlyPrefix) {
				delete(entry.Data, key)
			}
		}
	}

}

//WithPrefix sets a prefix filter to use in all subsequent logging
func (h *Hook) WithPrefix(prefix string) {
	h.hookOnlyPrefix = prefix
}

func (h *Hook) WithField(key string, value interface{}) {
	h.alwaysSentFields[key] = value
}

func (h *Hook) WithFields(fields logrus.Fields) {
	//Add all the new fields to the 'alwaysSentFields', possibly overwriting exising fields
	for key, value := range fields {
		h.alwaysSentFields[key] = value
	}
}

func (h *Hook) Fire(entry *logrus.Entry) error {
	if h.fireChannel != nil { // Async mode.
		h.fireChannel <- entry
		return nil
	}
	return h.sendMessage(entry)
}

func (h *Hook) sendMessage(entry *logrus.Entry) error {
	//make sure we always clear the hookonly fields from the entry
	defer h.filterHookOnly(entry)

	// Add in the alwaysSentFields. We don't override fields that are already set.
	for k, v := range h.alwaysSentFields {
		if _, inMap := entry.Data[k]; !inMap {
			entry.Data[k] = v
		}
	}

	//For a filteringHook, stop here
	if h.conn == nil {
		return nil
	}

	formatter := LogstashFormatter{Type: h.appName}
	if h.TimeFormat != "" {
		formatter.TimestampFormat = h.TimeFormat
	}

	dataBytes, err := formatter.FormatWithPrefix(entry, h.hookOnlyPrefix)
	if err != nil {
		return err
	}
	if _, err = h.conn.Write(dataBytes); err != nil {
		return err
	}
	return nil
}

func (h *Hook) Levels() []logrus.Level {
	return []logrus.Level{
		logrus.PanicLevel,
		logrus.FatalLevel,
		logrus.ErrorLevel,
		logrus.WarnLevel,
		logrus.InfoLevel,
		logrus.DebugLevel,
	}
}
