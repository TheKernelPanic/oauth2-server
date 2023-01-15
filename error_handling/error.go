package error_handling

type AuthError struct {
	Err              string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorUri         string `json:"error_uri,omitempty"`
}

func ErrorHandler(error string, description string, uri string) AuthError {
	return AuthError{Err: error, ErrorDescription: description, ErrorUri: uri}
}

func (e AuthError) Error() string {
	return e.Err
}
