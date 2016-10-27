package sand

type AuthenticationError struct {
	msg string
}

func (e AuthenticationError) Error() string {
	return e.msg
}
