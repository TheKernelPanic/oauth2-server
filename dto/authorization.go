package dto

type AuthorizeRequest struct {
	RedirectUri  string
	ClientID     string
	State        string
	ResponseType string
	Scope        string
}
