package models

type User struct {
	Email    string "json:email"
	Name    string "json:name"
	Password string "json:password"
  	Address string "json:address"
  	Phone string "json:phone"
}

type GoogleUser struct {
	Email    string "json:email"
	Name    string "json:name"
  	Address string "json:address"
  	Phone string "json:phone"
}

type UpdateResponse struct {
	Error     string "json:error"
	ErrorCode int    "json:code"
}

type CreateResponse struct {
	Error     string "json:error"
	ErrorCode int    "json:code"
}
