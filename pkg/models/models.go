package models

type Account struct {
	ID       int
	Email    string
	Username string
	Password string
}

type Snippet struct {
	ID      int
	User_ID int
	Title   string
	Content string
}

type UserAuthRequest struct {
	Email    string `json:"email"`
	Username string `json:"username"`
	Password string `json:"password"`
}

type UserAuthResponse struct {
	Username string `json:"username"`
	Token    string `json:"token"`
}
