package pii

// Error is a developer-friendly error wrapper that speaks privacy language.
// Its base error contains more technical details,
// and it can be enriched with meta-data, e.g., namespace and subject.
type Error struct {
	// Err is the base err
	Err                     error
	msg, namespace, subject string
}

func newErr(msg string) Error {
	return Error{
		msg: msg,
	}
}

// Message returns a short and primary message of the error.
//
// In contrast to Error() method, It doesn't include base error or meta-data in the return.
func (e Error) Message() string {
	return e.msg
}

// Subject returns the associated subject to the error if it exists.
func (e Error) Subject() string {
	if e.subject == "" {
		if err, ok := e.Err.(Error); ok {
			return err.Subject()
		}
	}
	return e.subject
}

// Namespace returns the associated namespace to the error if it exists.
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

// Error implements error interface.
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

// Is compares only messages of Errors to decide whether they are equal.
// Otherwise, the wrapped error will decide.
func (e Error) Is(err error) bool {
	if perr, ok := err.(Error); ok {
		return e.msg == perr.msg
	}

	return false
}
