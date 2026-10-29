// Package audit defines the issuance audit boundary.
package audit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"sync"
	"time"
)

var ErrUnavailable = errors.New("audit sink is unavailable")

type Event struct {
	Time        time.Time `json:"time"`
	Component   string    `json:"component"`
	Domain      string    `json:"domain,omitempty"`
	Action      string    `json:"action"`
	Outcome     string    `json:"outcome"`
	GrantID     string    `json:"grant_id,omitempty"`
	RequestID   string    `json:"request_id,omitempty"`
	OperationID string    `json:"operation_id,omitempty"`
	IdentityRef string    `json:"identity_ref,omitempty"`
	Reason      string    `json:"reason,omitempty"`
}

type Sink interface {
	Record(context.Context, Event) error
}

type NopSink struct{}

func (NopSink) Record(context.Context, Event) error { return nil }

type JSONSink struct {
	mu     sync.Mutex
	writer io.Writer
}

func NewJSONSink(writer io.Writer) *JSONSink {
	return &JSONSink{writer: writer}
}

func (s *JSONSink) Record(_ context.Context, event Event) error {
	if s == nil || s.writer == nil {
		return ErrUnavailable
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	raw, err := json.Marshal(event)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	raw = append(raw, '\n')
	for len(raw) > 0 {
		written, err := s.writer.Write(raw)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrShortWrite
		}
		raw = raw[written:]
	}
	return nil
}

type MemorySink struct {
	mu     sync.Mutex
	events []Event
}

func (s *MemorySink) Record(_ context.Context, event Event) error {
	if s == nil {
		return ErrUnavailable
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	s.mu.Lock()
	s.events = append(s.events, event)
	s.mu.Unlock()
	return nil
}

func (s *MemorySink) Events() []Event {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Event(nil), s.events...)
}

func Record(ctx context.Context, sink Sink, event Event) error {
	if sink == nil {
		return ErrUnavailable
	}
	if ctx == nil {
		ctx = context.Background()
	}
	return sink.Record(ctx, event)
}
