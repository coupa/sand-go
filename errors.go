package sand

//AuthenticationError is returned when the client receives a 401 accessing the authentication
//service or the target service
type AuthenticationError struct {
	Message string `json:"message"`
}

func (e AuthenticationError) Error() string {
	return e.Message
}

//ServiceUnauthorizedError when service receives 401 from Sand while verifying a client token.
type ServiceUnauthorizedError struct {
	Message string `json:"message"`
}

func (e ServiceUnauthorizedError) Error() string {
	return e.Message
}
