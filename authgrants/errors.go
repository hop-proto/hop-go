package authgrants

import "errors"

// ErrUnknownMessage used when msgtype does not match any of the authorization grant protocol defined messages.
var ErrUnknownMessage = errors.New("received message with unknown message type")

// ErrIntentDenied indicates an intent request was denied
var ErrIntentDenied = errors.New("received intent denied message")
