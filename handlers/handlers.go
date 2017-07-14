package handlers

import (
	"database/sql"
	"fmt"
	"encoding/json"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"net/http"
	"log"
	"github.com/unrolled/render"
	jwt "github.com/dgrijalva/jwt-go"
	"time"
	"context"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io/ioutil"
	"../db"
	"../models"
)

type Claims struct {
    Email string `json:"email"`
	Account_Type string `json:"account_type"`
    jwt.StandardClaims
}

// Google OAuth Configuration
var (
    	googleOauthConfig = &oauth2.Config {
        RedirectURL:    "http://localhost:9000/googleCallback",
        ClientID:     "220079914883-hrk0hankcfp9j64tm53d8n63fqkk52oj.apps.googleusercontent.com",
        ClientSecret: "pJXym9_nY0czicpH1k1qrVhf",
        Scopes:       []string{"https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email"},
        Endpoint:     google.Endpoint,
    }

	// Some random string, random for each request
    oauthStateString = "random"
)

type Key int
const MyKey Key = 0

func ServePage(res http.ResponseWriter, req *http.Request, template string, data map[string]string) {
	r := render.New(render.Options{Directory: "templates",})
	r.HTML(res, http.StatusOK, template, data)
}

// Middleware to protect private pages
func Validate(protectedPage http.HandlerFunc) http.HandlerFunc {
    return http.HandlerFunc(func(res http.ResponseWriter, req *http.Request){

        // If no Auth cookie is set then return a 404 not found
        cookie, err := req.Cookie("Auth")
        if err != nil {
            http.NotFound(res, req)
            return
        }

        // Return a Token using the cookie
        token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error){
            // Make sure token's signature wasn't changed
            if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
                return nil, fmt.Errorf("Unexpected siging method")
            }
            return []byte("secret"), nil
        })

        if err != nil {
            http.NotFound(res, req)
            return
        }

        // Grab the tokens claims and pass it into the original request
        if claims, ok := token.Claims.(*Claims); ok && token.Valid {
            ctx := context.WithValue(req.Context(), MyKey, *claims)
            protectedPage(res, req.WithContext(ctx))
        } else {
            http.NotFound(res, req)
            return
        }
    })
}

func getTokenDetails(req *http.Request) (string, string) {
	// If no Auth cookie is set then return a 404 not found
	cookie, err := req.Cookie("Auth")
	if err != nil {
		return "", ""
	}

	// Return a Token using the cookie
	token, err := jwt.ParseWithClaims(cookie.Value, &Claims{}, func(token *jwt.Token) (interface{}, error){
        // Make sure token's signature wasn't changed
        if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
            return nil, fmt.Errorf("Unexpected siging method")
        }
        return []byte("secret"), nil
    })

	if err != nil {
		return "", ""
	}

	claims := token.Claims.(*Claims)
	return claims.Email, claims.Account_Type
}

func setToken(res http.ResponseWriter, req *http.Request, email string, account_type string) {
    // Expires the token and cookie in 1 hour
    expireToken := time.Now().Add(time.Hour * 1).Unix()
    expireCookie := time.Now().Add(time.Hour * 1)

    // We'll manually assign the claims but in production you'd insert values from a database
    claims := Claims {
        email,
		account_type,
        jwt.StandardClaims {
            ExpiresAt: expireToken,
            Issuer: "localhost:9000",
        },
    }

    // Create the token using your claims
    token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

    // Signs the token with a secret.
    signedToken, _ := token.SignedString([]byte("secret"))

    // Place the token in the client's cookie
    cookie := http.Cookie{Name: "Auth", Value: signedToken, Expires: expireCookie, HttpOnly: true}
    http.SetCookie(res, &cookie)
}

func LoginHandlerGet(res http.ResponseWriter, req *http.Request) {
	email, _ := getTokenDetails(req)

	if email != "" {
		data := map[string]string{
			"email": email, 
		}
		ServePage(res, req, "welcome", data)
	} else {
		ServePage(res, req, "login", nil)
	}
}

func LoginHandlerPost(res http.ResponseWriter, req *http.Request) {
	email := req.FormValue("email")
	password := req.FormValue("password")

	// Grab from the database
    var databaseEmail string
    var databasePassword  string

    // Search the database for the email provided
    // If it exists grab the password for validation
    err := db.Database.QueryRow("SELECT email, password FROM users WHERE email=?", email).Scan(&databaseEmail, &databasePassword)
    // If not then redirect to the login page
    if err != nil {
    	fmt.Println(err)
        http.Redirect(res, req, "/login", 301)
        return
    }

    // Validate the password
    err = bcrypt.CompareHashAndPassword([]byte(databasePassword), []byte(password))
    // If wrong password redirect to the login
    if err != nil {
    	fmt.Println(err)
        http.Redirect(res, req, "/login", 301)
        return
    }

	setToken(res, req, email, "normal")
	http.Redirect(res, req, "/profile", 301)
}

func LogoutHandler(res http.ResponseWriter, req *http.Request) {
	deleteCookie := http.Cookie{Name: "Auth", Value: "none", Expires: time.Now()}
  	http.SetCookie(res, &deleteCookie)
  	return
}

func SignupHandlerGet(res http.ResponseWriter, req *http.Request) {
	email, _ := getTokenDetails(req)

	if email != "" {
		data := map[string]string{
			"email": email, 
		}
		ServePage(res, req, "welcome", data)
	} else {
		ServePage(res, req, "signup", nil)
	}
}

func SignupHandlerPost(res http.ResponseWriter, req *http.Request) {
	NewUser := models.User{}
	NewUser.Email = req.FormValue("email")
	NewUser.Password = req.FormValue("password")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(NewUser.Password), bcrypt.DefaultCost)

	output, err := json.Marshal(NewUser)
	fmt.Println(string(output))
	if err != nil {
		fmt.Println("Something went wrong!")
	}

	Response := models.CreateResponse{}
	q, err := db.Database.Exec("INSERT INTO users (email, password) values (?, ?)", NewUser.Email, hashedPassword)
	if err != nil {
		errorMessage, errorCode := db.ParseDBError(err.Error())
		fmt.Println(errorMessage)
		error, httpCode, msg := ErrorMessages(errorCode)
		Response.Error = msg
		fmt.Println(msg)
		Response.ErrorCode = error
		http.Error(res, "Conflict", httpCode)
	}
	fmt.Println(q)

	setToken(res, req, NewUser.Email, "normal")
	http.Redirect(res, req, "/profile/update", 301)
}

func ProfileHandler(res http.ResponseWriter, req *http.Request) {
	email, account_type := getTokenDetails(req)
	var name sql.NullString
	var address sql.NullString
	var phone sql.NullString
	var err error

	if account_type == "normal" {
		err = db.Database.QueryRow("SELECT name, address, phone FROM users WHERE email=?", email).Scan(&name, &address, &phone)
	} else {
		err = db.Database.QueryRow("SELECT name, address, phone FROM google_users WHERE email=?", email).Scan(&name, &address, &phone)
	}

	// If not then redirect to the login page
	if err != nil {
		fmt.Println(err)
		return
	}

	data := map[string]string{
		"email": email, 
		"name": name.String, 
		"address": address.String, 
		"phone": phone.String,
	}

	ServePage(res, req, "profile", data)
}


func ProfileUpdateHandlerGet(res http.ResponseWriter, req *http.Request) {
	email, account_type := getTokenDetails(req)
	var name sql.NullString
	var address sql.NullString
	var phone sql.NullString
	var err error

	if account_type == "normal" {
		err = db.Database.QueryRow("SELECT name, address, phone FROM users WHERE email=?", email).Scan(&name, &address, &phone)
	} else {
		err = db.Database.QueryRow("SELECT name, address, phone FROM google_users WHERE email=?", email).Scan(&name, &address, &phone)
	}

	// If not then redirect to the login page
	if err != nil {
		fmt.Println(err)
		return
	}

	data := map[string]string{
		"email": email, 
		"name": name.String, 
		"address": address.String, 
		"phone": phone.String,
	}
	ServePage(res, req, "edit_info", data)
}

func ProfileUpdateHandlerPost(res http.ResponseWriter, req *http.Request) {
	original_email, account_type := getTokenDetails(req)

	Response := models.UpdateResponse{}
	email := req.FormValue("email")
	name := req.FormValue("name")
	address := req.FormValue("address")
	phone := req.FormValue("phone")

	var userCount int
	var err error

	if account_type == "normal" {
		err = db.Database.QueryRow("SELECT count(email) from users where email=?", original_email).Scan(&userCount)
	} else {
		err = db.Database.QueryRow("SELECT count(email) from google_users where email=?", original_email).Scan(&userCount)
	}

	if userCount == 0 {
		error, httpCode, msg := ErrorMessages(404)
		log.Println(error)
		log.Println(res, msg, httpCode)
		Response.Error = msg
		Response.ErrorCode = httpCode
		http.Error(res, msg, httpCode)

	} else if err != nil {

	} else {
		if account_type == "normal" {
			_, err = db.Database.Exec("UPDATE users set email=?, name=?, address=?, phone=? where email=?", email, name, address, phone, original_email)
		} else {
			_, err = db.Database.Exec("UPDATE google_users set email=?, name=?, address=?, phone=? where email=?", email, name, address, phone, original_email)
		}

		if err != nil {
			_, errorCode := db.ParseDBError(err.Error())
			_, httpCode, msg := ErrorMessages(errorCode)

			Response.Error = msg
			Response.ErrorCode = httpCode
			http.Error(res, msg, httpCode)
		} else {
			Response.Error = "success"
			Response.ErrorCode = 0

			if account_type == "normal" && email != original_email {
				setToken(res, req, email, "normal")
			}
			http.Redirect(res, req, "/profile", 301)
		}
	}
}

func GoogleLoginHandler(res http.ResponseWriter, req *http.Request) {
    url := googleOauthConfig.AuthCodeURL(oauthStateString)
    http.Redirect(res, req, url, http.StatusTemporaryRedirect)
}

func GoogleCallbackHandler(res http.ResponseWriter, req *http.Request) {
	state := req.FormValue("state")
    if state != oauthStateString {
        fmt.Printf("invalid oauth state, expected '%s', got '%s'\n", oauthStateString, state)
        http.Redirect(res, req, "/", http.StatusTemporaryRedirect)
        return
    }

    code := req.FormValue("code")
    token, err := googleOauthConfig.Exchange(oauth2.NoContext, code)
    if err != nil {
        fmt.Println("Code exchange failed with '%s'\n", err)
        http.Redirect(res, req, "/", http.StatusTemporaryRedirect)
        return
    }

    response, err := http.Get("https://www.googleapis.com/oauth2/v2/userinfo?access_token=" + token.AccessToken)

    defer response.Body.Close()
    contents, err := ioutil.ReadAll(response.Body)
    
    //fmt.Fprintf(res, "Content: %s\n", contents)

    var data map[string]interface{}
	err = json.Unmarshal([]byte(contents), &data)
	if err != nil {
	    panic(err)
	}
	fmt.Println(data["email"])
	email := data["email"].(string)

	setToken(res, req, email, "google")
	var userCount int
	err = db.Database.QueryRow("SELECT count(email) from google_users where email=?", email).Scan(&userCount)
	if err != nil {
		fmt.Println(err)
		return
	}

	if userCount == 0 {
		_, err = db.Database.Exec("INSERT INTO google_users (email) values (?)", email)
		if err != nil {
			fmt.Println(err)
			return
		}
		http.Redirect(res, req, "/profile/update", 301)
	}
	
	http.Redirect(res, req, "/profile", 301)
}

func PasswordForgetHandlerGet(res http.ResponseWriter, req *http.Request) {
	email, _ := getTokenDetails(req)

	if email != "" {
		data := map[string]string{
			"email": email, 
		}
		ServePage(res, req, "welcome", data)
	} else {
		ServePage(res, req, "password_forget", nil)
	}
}

func PasswordForgetHandlerPost(res http.ResponseWriter, req *http.Request) {
	email := req.FormValue("email")
	random_string := GenerateRandomString()

	_, err := db.Database.Exec("DELETE FROM password_reset where email=?", email)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = db.Database.Exec("INSERT INTO password_reset (email, random_string) values (?, ?)", email, random_string)
	if err != nil {
		fmt.Println(err)
		return
	}

	SendRequestReset(email, random_string, "localhost:9000")
}

func PasswordUpdateHandlerGet(res http.ResponseWriter, req *http.Request) {
	params := mux.Vars(req)
	random_string := params["random_string"]

	var userCount int
	err := db.Database.QueryRow("SELECT COUNT(email) FROM password_reset WHERE random_string=?", random_string).Scan(&userCount)
	if err != nil {
		fmt.Println(err)
		return
	}

	if userCount == 0 {
		http.NotFound(res, req)
        return
	} else {
		ServePage(res, req, "password_update", nil)
	}
}

func PasswordUpdateHandlerPost(res http.ResponseWriter, req *http.Request) {
	params := mux.Vars(req)
	random_string := params["random_string"]
	password := req.FormValue("password")

	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	var email string

	err = db.Database.QueryRow("SELECT email FROM password_reset WHERE random_string=?", random_string).Scan(&email)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = db.Database.Exec("UPDATE users SET password=? WHERE email=?", hashedPassword, email)
	if err != nil {
		fmt.Println(err)
		return
	}

	_, err = db.Database.Exec("DELETE FROM password_reset where email=?", email)
	if err != nil {
		fmt.Println(err)
		return
	}
}

