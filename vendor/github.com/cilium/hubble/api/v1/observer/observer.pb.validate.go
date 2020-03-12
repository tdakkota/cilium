// Code generated by protoc-gen-validate. DO NOT EDIT.
// source: observer/observer.proto

package observer

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/golang/protobuf/ptypes"
)

// ensure the imports are used
var (
	_ = bytes.MinRead
	_ = errors.New("")
	_ = fmt.Print
	_ = utf8.UTFMax
	_ = (*regexp.Regexp)(nil)
	_ = (*strings.Reader)(nil)
	_ = net.IPv4len
	_ = time.Duration(0)
	_ = (*url.URL)(nil)
	_ = (*mail.Address)(nil)
	_ = ptypes.DynamicAny{}
)

// define the regex for a UUID once up-front
var _observer_uuidPattern = regexp.MustCompile("^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")

// Validate checks the field values on ServerStatusRequest with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *ServerStatusRequest) Validate() error {
	if m == nil {
		return nil
	}

	return nil
}

// ServerStatusRequestValidationError is the validation error returned by
// ServerStatusRequest.Validate if the designated constraints aren't met.
type ServerStatusRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ServerStatusRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ServerStatusRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ServerStatusRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ServerStatusRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ServerStatusRequestValidationError) ErrorName() string {
	return "ServerStatusRequestValidationError"
}

// Error satisfies the builtin error interface
func (e ServerStatusRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sServerStatusRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ServerStatusRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ServerStatusRequestValidationError{}

// Validate checks the field values on ServerStatusResponse with the rules
// defined in the proto definition for this message. If any rules are
// violated, an error is returned.
func (m *ServerStatusResponse) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for NumFlows

	// no validation rules for MaxFlows

	return nil
}

// ServerStatusResponseValidationError is the validation error returned by
// ServerStatusResponse.Validate if the designated constraints aren't met.
type ServerStatusResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e ServerStatusResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e ServerStatusResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e ServerStatusResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e ServerStatusResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e ServerStatusResponseValidationError) ErrorName() string {
	return "ServerStatusResponseValidationError"
}

// Error satisfies the builtin error interface
func (e ServerStatusResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sServerStatusResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = ServerStatusResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = ServerStatusResponseValidationError{}

// Validate checks the field values on GetFlowsRequest with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *GetFlowsRequest) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for Number

	// no validation rules for Follow

	for idx, item := range m.GetBlacklist() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return GetFlowsRequestValidationError{
					field:  fmt.Sprintf("Blacklist[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	for idx, item := range m.GetWhitelist() {
		_, _ = idx, item

		if v, ok := interface{}(item).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return GetFlowsRequestValidationError{
					field:  fmt.Sprintf("Whitelist[%v]", idx),
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	if v, ok := interface{}(m.GetSince()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return GetFlowsRequestValidationError{
				field:  "Since",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	if v, ok := interface{}(m.GetUntil()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return GetFlowsRequestValidationError{
				field:  "Until",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	return nil
}

// GetFlowsRequestValidationError is the validation error returned by
// GetFlowsRequest.Validate if the designated constraints aren't met.
type GetFlowsRequestValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e GetFlowsRequestValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e GetFlowsRequestValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e GetFlowsRequestValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e GetFlowsRequestValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e GetFlowsRequestValidationError) ErrorName() string { return "GetFlowsRequestValidationError" }

// Error satisfies the builtin error interface
func (e GetFlowsRequestValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sGetFlowsRequest.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = GetFlowsRequestValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = GetFlowsRequestValidationError{}

// Validate checks the field values on GetFlowsResponse with the rules defined
// in the proto definition for this message. If any rules are violated, an
// error is returned.
func (m *GetFlowsResponse) Validate() error {
	if m == nil {
		return nil
	}

	// no validation rules for NodeName

	if v, ok := interface{}(m.GetTime()).(interface{ Validate() error }); ok {
		if err := v.Validate(); err != nil {
			return GetFlowsResponseValidationError{
				field:  "Time",
				reason: "embedded message failed validation",
				cause:  err,
			}
		}
	}

	switch m.ResponseTypes.(type) {

	case *GetFlowsResponse_Flow:

		if v, ok := interface{}(m.GetFlow()).(interface{ Validate() error }); ok {
			if err := v.Validate(); err != nil {
				return GetFlowsResponseValidationError{
					field:  "Flow",
					reason: "embedded message failed validation",
					cause:  err,
				}
			}
		}

	}

	return nil
}

// GetFlowsResponseValidationError is the validation error returned by
// GetFlowsResponse.Validate if the designated constraints aren't met.
type GetFlowsResponseValidationError struct {
	field  string
	reason string
	cause  error
	key    bool
}

// Field function returns field value.
func (e GetFlowsResponseValidationError) Field() string { return e.field }

// Reason function returns reason value.
func (e GetFlowsResponseValidationError) Reason() string { return e.reason }

// Cause function returns cause value.
func (e GetFlowsResponseValidationError) Cause() error { return e.cause }

// Key function returns key value.
func (e GetFlowsResponseValidationError) Key() bool { return e.key }

// ErrorName returns error name.
func (e GetFlowsResponseValidationError) ErrorName() string { return "GetFlowsResponseValidationError" }

// Error satisfies the builtin error interface
func (e GetFlowsResponseValidationError) Error() string {
	cause := ""
	if e.cause != nil {
		cause = fmt.Sprintf(" | caused by: %v", e.cause)
	}

	key := ""
	if e.key {
		key = "key for "
	}

	return fmt.Sprintf(
		"invalid %sGetFlowsResponse.%s: %s%s",
		key,
		e.field,
		e.reason,
		cause)
}

var _ error = GetFlowsResponseValidationError{}

var _ interface {
	Field() string
	Reason() string
	Key() bool
	Cause() error
	ErrorName() string
} = GetFlowsResponseValidationError{}
