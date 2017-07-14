package handlers

import (
	_ "github.com/go-sql-driver/mysql"
	"net/http"
	"math/rand"
	"gopkg.in/gomail.v2"
	"time"
)

// Email Configuration
var EMAIL_HOST string = "smtp.gmail.com"
var EMAIL_PORT int = 587
var EMAIL_USERNAME string = "vanpersie2009@gmail.com"
var EMAIL_PASSWORD string = "Nghia2309"

func ErrorMessages(err int64) (int, int, string) {
	errorMessage := ""
	statusCode := 200
	errorCode := 0
	switch err {
	case 1062:
		errorMessage = http.StatusText(409)
		errorCode = 10
		statusCode = http.StatusConflict
	default:
		errorMessage = http.StatusText(int(err))
		errorCode = 0
		statusCode = int(err)
	}

	return errorCode, statusCode, errorMessage
}

func GenerateRandomString() string{
	r := rand.New(rand.NewSource(time.Now().UnixNano()))
	const chars = "abcdefghijklmnopqrstuvwxyz0123456789"
	result := make([]byte, 20)
	for i := range result {
		result[i] = chars[r.Intn(len(chars))]
	}
	return string(result)
}

func SendRequestReset(email, u string, domainname string) bool {
	link := "http://" + domainname + "/password_update/" + u
	msg := gomail.NewMessage()
	msg.SetAddressHeader("From", EMAIL_USERNAME, "Test Corporation")
	msg.SetHeader("To", email)
	msg.SetHeader("Subject", "Request Password Reset for Test Corporation")
	msg.SetBody("text/html", "To reset your password, please click on the link: <a href=\""+link+
		"\">"+link+"</a><br><br>Best Regards,<br>Test Corporation")
	m := gomail.NewDialer(EMAIL_HOST, EMAIL_PORT, EMAIL_USERNAME, EMAIL_PASSWORD)
	
	// Send the email
	if err := m.DialAndSend(msg); err != nil {
	    panic(err)
	}
	return true
}