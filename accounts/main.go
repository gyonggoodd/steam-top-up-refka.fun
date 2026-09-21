package main

import (
	_ "://github.com"
	"database/sql"
	"fmt"
	"log"
)

func checkUser() {
	db, err := sql.Open("postgres", "user=postgres password=secret dbname=test sslmode=disable")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer db.Close()

	rows, err := db.Query("SELECT id, Email, Username, Password_hash, CreatedAt FROM User")
	if err != nil {
		log.Fatal(err)
		return
	}
	defer rows.Close()

	var user []User

	for rows.Next() {
		var u User
		err := rows.Scan(&u.Id, &u.Email, &u.Username, &u.Password_hash, &u.CreatedAt)
		if err != nil {
			log.Fatal(err)
			return
		}
		user = append(user, u)
	}

	if err = rows.Err(); err != nil {
		log.Fatal(err)
		return
	}
	fmt.Println()
}

func createUser() {

}

func main() {
	checkUser()
}
