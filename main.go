package main

//https://www.sohamkamani.com/golang/jwt-authentication/

import (
	"encoding/json"
	"github.com/golang-jwt/jwt"
	"log"
	"net/http"
	"time"
)

var jwtKey = []byte("its_my_secret_key")

var users = map[string]string{
	"repa":     "11223344",
	"janeSalt": "44332211",
	"DP_WEB":   "In23gB08",
}

type Credentials struct {
	Username string `json:"login"`
	Password string `json:"password"`
}

type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

type SigninResponse struct {
	Token string `json:"token"`
}

func setupCorsResponse(w *http.ResponseWriter, r *http.Request) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")

	(*w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Authorization")
}

func signin(w http.ResponseWriter, r *http.Request) {
	var creds Credentials

	// Get the JSON body and decode into credentials
	err := json.NewDecoder(r.Body).Decode(&creds)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	expectedPassword, ok := users[creds.Username]

	if !ok || expectedPassword != creds.Password {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	experationTime := time.Now().Add(24 * time.Hour)

	claims := &Claims{
		Username: creds.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: experationTime.Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	tokenSignedString, err := token.SignedString(jwtKey)

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}

	err = json.NewEncoder(w).Encode(SigninResponse{Token: tokenSignedString})

	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		return
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	setupCorsResponse(&w, r)

	if (*r).Method == "OPTIONS" {
		return
	}

	path := r.URL.Path

	switch path {
	case "/signin":
		signin(w, r)
	default:
		http.NotFound(w, r)
	}
}

func main() {
	http.HandleFunc("/", handler)

	log.Fatal(http.ListenAndServe(":8080", nil))
}
