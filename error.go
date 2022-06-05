package pii

import (
	"errors"
)

// Error is a developer friendly error wrapper that speaks privacy language.
// It's base error contains more technical details,
// and it can be enriched with meta-data e.g namespace and subjectID.
type Error struct {
	msg, namespace, subject string
	// Err is the base err
	Err error
}

func newErr(msg string) Error {
	return Error{
		msg: msg,
	}
}

func IsError(err error) (bool, *Error) {
	terr := Error{}
	if ok := errors.As(err, &terr); ok {
		return true, &terr
	}
	return false, nil
}

func (e Error) Message() string {
	return e.msg
}

func (e Error) Subject() string {
	if e.subject == "" {
		if err, ok := e.Err.(Error); ok {
			return err.Subject()
		}
	}
	return e.subject
}

func (e Error) Namespace() string {
	if e.namespace == "" {
		if err, ok := e.Err.(Error); ok {
			return err.Namespace()
		}
	}
	return e.namespace
}

func (e Error) withNamespace(nspace string) Error {
	e.namespace = nspace
	return e
}

func (e Error) withSubject(sub string) Error {
	e.subject = sub
	return e
}

func (e Error) withBase(err error) Error {
	e.Err = err
	return e
}

func (e Error) Error() string {
	str := "" + e.msg
	if n := e.Namespace(); n != "" {
		str += " [ns:'" + n + "']"

	}

	if s := e.Subject(); s != "" {
		str += " [sub:'" + s + "']"
	}

	if e.Err != nil {
		str += ": " + e.Err.Error()
	}

	return str
}

func (e Error) Unwrap() error {
	return e.Err
}

func (e Error) Is(err error) bool {
	if perr, ok := err.(Error); ok {
		return e.msg == perr.msg
	}

	return false
}
