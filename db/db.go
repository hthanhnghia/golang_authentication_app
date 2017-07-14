package db

import (
	"database/sql"
	_ "github.com/go-sql-driver/mysql"
	"github.com/gorilla/mux"
	"strings"
	"strconv"
	"fmt"
)

var Database *sql.DB
var Routes *mux.Router
var Format string

func StartDatabaseServer() {
	dbconnection, err := sql.Open("mysql", "root:nghia2309@/authentication")
	if err != nil {
		fmt.Println(err)
	}
	Database = dbconnection
}

func ParseDBError(err string) (string, int64) {
	Parts := strings.Split(err, ":")
	errorMessage := Parts[1]
	Code := strings.Split(Parts[0], "Error ")
	errorCode, _ := strconv.ParseInt(Code[1], 10, 32)
	return errorMessage, errorCode
}

