package dto

type AuthorizeRequest struct {
	RedirectUri  string
	ClientID     string
	State        string
	ResponseType string
	Scope        string
}

type RedirectResponse struct {
	StatusCode uint16
	Uri        string
	State      string
}
