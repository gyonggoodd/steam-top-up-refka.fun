package main

import (
	"time"
)

type User struct {
	Id            int       `json:"id"`
	Email         string    `json:"login"`
	Username      string    `json:"username"`
	Password_hash string    `json:"password_hash"`
	CreatedAt     time.Time `json:"created_at"`
}
