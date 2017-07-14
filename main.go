package main
 
import (
	"./db"
	"./routers"
)

func main() {
	db.StartDatabaseServer()
	routers.Init()
}