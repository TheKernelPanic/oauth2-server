package error_handling

import "oauth2/config"

type AuthError struct {
	Err              string `json:"error"`
	ErrorDescription string `json:"error_description"`
	ErrorUri         string `json:"error_uri,omitempty"`
}

func ErrorHandler(error string, description string, uri string) AuthError {

	if uri != "" {
		uri = config.RfcDocsRefUrl + uri
	}
	return AuthError{Err: error, ErrorDescription: description, ErrorUri: uri}
}

func (e AuthError) Error() string {
	return e.Err
}
