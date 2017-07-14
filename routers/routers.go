package routers

import (
	"github.com/gorilla/mux"
  "net/http"
  "../handlers"
)

var Routes *mux.Router

func Init() {
  Routes := mux.NewRouter()
  Routes.Handle("/", http.FileServer(http.Dir("./views/")))
  Routes.PathPrefix("/static/").Handler(http.StripPrefix("/static/", http.FileServer(http.Dir("./static/"))))

  Routes.HandleFunc("/login", handlers.LoginHandlerGet).Methods("GET")
  Routes.HandleFunc("/login", handlers.LoginHandlerPost).Methods("POST")
  Routes.HandleFunc("/logout", handlers.Validate(handlers.LogoutHandler))

  Routes.HandleFunc("/googleLogin", handlers.GoogleLoginHandler)
  Routes.HandleFunc("/googleCallback", handlers.GoogleCallbackHandler)

  Routes.HandleFunc("/signup", handlers.SignupHandlerGet).Methods("GET")
  Routes.HandleFunc("/signup", handlers.SignupHandlerPost).Methods("POST")

  Routes.HandleFunc("/profile", handlers.Validate(handlers.ProfileHandler))

  Routes.HandleFunc("/profile/update", handlers.Validate(handlers.ProfileUpdateHandlerGet)).Methods("GET")
  Routes.HandleFunc("/profile/update", handlers.Validate(handlers.ProfileUpdateHandlerPost)).Methods("POST")

  Routes.HandleFunc("/password_forget", handlers.PasswordForgetHandlerGet).Methods("GET")
  Routes.HandleFunc("/password_forget", handlers.PasswordForgetHandlerPost).Methods("POST")

  Routes.HandleFunc("/password_update/{random_string}", handlers.PasswordUpdateHandlerGet).Methods("GET")
  Routes.HandleFunc("/password_update/{random_string}", handlers.PasswordUpdateHandlerPost).Methods("POST")

  http.ListenAndServe(":9000", Routes)
}
