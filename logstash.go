package logrustash

import (
	"fmt"
	"io/ioutil"
	"math"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	gas "github.com/xaionaro-go/goautosocket"
)

// Hook represents a connection to a Logstash instance
type Hook struct {
	sync.RWMutex
	conn                     net.Conn
	protocol                 string
	address                  string
	appName                  string
	alwaysSentFields         logrus.Fields
	hookOnlyPrefix           string
	TimeFormat               string
	fireChannel              chan *logrus.Entry
	AsyncBufferSize          int
	WaitUntilBufferFrees     bool
	Timeout                  time.Duration // Timeout for sending message.
	MaxSendRetries           int           // Declares how many times we will try to resend message.
	ReconnectBaseDelay       time.Duration // First reconnect delay.
	ReconnectDelayMultiplier float64       // Base multiplier for delay before reconnect.
	MaxReconnectRetries      int           // Declares how many times we will try to reconnect.
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
	var (
		conn net.Conn
		err  error
	)
	switch protocol {
	case "tcp":
		conn, err = gas.Dial("tcp", address)
	default:
		conn, err = net.Dial(protocol, address)
	}
	if err != nil {
		return nil, err
	}

	hook, err := NewHookWithFieldsAndConnAndPrefix(conn, appName, alwaysSentFields, prefix)
	hook.protocol = protocol
	hook.address = address

	return hook, err
}

// NewAsyncHookWithFieldsAndPrefix creates a new hook to a Logstash instance, which listens on
// `protocol`://`address`. alwaysSentFields will be sent with every log entry. prefix is used to select fields to filter.
// Logs will be sent asynchronously.
func NewAsyncHookWithFieldsAndPrefix(protocol, address, appName string, alwaysSentFields logrus.Fields, prefix string) (*Hook, error) {
	hook, err := NewHookWithFieldsAndPrefix(protocol, address, appName, alwaysSentFields, prefix)
	if err != nil {
		return nil, err
	}
	hook.AsyncBufferSize = 8192
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

// NewHookWithFieldsAndConnAndPrefix creates a new hook to a Logstash instance using the suppolied connection and prefix.
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
	h.fireChannel = make(chan *logrus.Entry, h.AsyncBufferSize)

	go func() {
		for entry := range h.fireChannel {
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

// WithPrefix sets a prefix filter to use in all subsequent logging
func (h *Hook) WithPrefix(prefix string) {
	h.hookOnlyPrefix = prefix
}

// WithField add field with value that will be sent with each message
func (h *Hook) WithField(key string, value interface{}) {
	h.alwaysSentFields[key] = value
}

// WithFields add fields with values that will be sent with each message
func (h *Hook) WithFields(fields logrus.Fields) {
	// Add all the new fields to the 'alwaysSentFields', possibly overwriting existing fields
	for key, value := range fields {
		h.alwaysSentFields[key] = value
	}
}

// Fire send message to logstash.
// In async mode log message will be dropped if message buffer is full.
// If you want wait until message buffer frees – set WaitUntilBufferFrees to true.
func (h *Hook) Fire(entry *logrus.Entry) error {
	if h.fireChannel != nil { // Async mode.
		select {
		case h.fireChannel <- entry:
		default:
			if h.WaitUntilBufferFrees {
				h.fireChannel <- entry // Blocks the goroutine because buffer is full.

				return nil
			}

			// Drop message by default.
		}

		return nil
	}

	return h.sendMessage(entry)
}

func (h *Hook) sendMessage(entry *logrus.Entry) error {
	// Make sure we always clear the hook only fields from the entry
	defer h.filterHookOnly(entry)

	// Add in the alwaysSentFields. We don't override fields that are already set.
	for k, v := range h.alwaysSentFields {
		if _, inMap := entry.Data[k]; !inMap {
			entry.Data[k] = v
		}
	}

	// For a filteringHook, stop here
	h.RLock()
	if h.conn == nil {
		h.RUnlock()

		return nil
	}
	h.RUnlock()

	formatter := LogstashFormatter{Type: h.appName}
	if h.TimeFormat != "" {
		formatter.TimestampFormat = h.TimeFormat
	}

	dataBytes, err := formatter.FormatWithPrefix(entry, h.hookOnlyPrefix)
	if err != nil {
		return err
	}

	return h.performSend(dataBytes, 0)
}

// performSend tries to send data recursively.
// sendRetries is the actual number of attempts to resend message.
func (h *Hook) performSend(data []byte, sendRetries int) error {
	if h.Timeout > 0 {
		h.Lock()
		h.conn.SetWriteDeadline(time.Now().Add(h.Timeout))
		h.Unlock()
	}

	h.Lock()
	_, err := h.conn.Write(data)
	h.Unlock()

	if err != nil {
		file := fmt.Sprintf("/tmp/logrustash-%d.tmp", time.Now().UnixNano())
		ioutil.WriteFile(file, data, 0644)
		fmt.Printf("Wrote message content to %s\n", file)
		return h.processSendError(err, data, sendRetries)
	}

	return nil
}

func (h *Hook) processSendError(err error, data []byte, sendRetries int) error {
	netErr, ok := err.(net.Error)
	if !ok {
		return err
	}

	if h.isNeedToResendMessage(netErr, sendRetries) {
		return h.performSend(data, sendRetries+1)
	}

	if !netErr.Temporary() && h.MaxReconnectRetries > 0 {
		if err := h.reconnect(0); err != nil {
			return fmt.Errorf("Couldn't reconnect to logstash: %s. The reason of reconnect: %s", err, netErr)
		}

		return h.performSend(data, 0)
	}

	return err
}

// TODO Check reconnect for NOT ASYNC mode.
// The hook will reconnect to Logstash several times with increasing sleep duration between each reconnect attempt.
// Sleep duration calculated as product of ReconnectBaseDelay by ReconnectDelayMultiplier to the power of reconnectRetries.
// reconnectRetries is the actual number of attempts to reconnect.
func (h *Hook) reconnect(reconnectRetries int) error {
	if h.protocol == "" || h.address == "" {
		return fmt.Errorf("Can't reconnect because current configuration doesn't support it")
	}

	// Sleep before reconnect.
	delay := float64(h.ReconnectBaseDelay) * math.Pow(h.ReconnectDelayMultiplier, float64(reconnectRetries))
	time.Sleep(time.Duration(delay))

	conn, err := gas.Dial(h.protocol, h.address)

	// Oops. Can't connect. No problem. Let's try again.
	if err != nil {
		if !h.isNeedToReconnect(reconnectRetries) {
			// We have reached limit of re-connections.
			return err
		}

		return h.reconnect(reconnectRetries + 1)
	}

	h.Lock()
	h.conn = conn
	h.Unlock()

	return nil
}

func (h *Hook) isNeedToResendMessage(err net.Error, sendRetries int) bool {
	return (err.Temporary() || err.Timeout()) && sendRetries < h.MaxSendRetries
}

func (h *Hook) isNeedToReconnect(reconnectRetries int) bool {
	return reconnectRetries < h.MaxReconnectRetries
}

// Levels specifies "active" log levels.
// Log messages with this levels will be sent to logstash.
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
