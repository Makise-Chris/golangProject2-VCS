package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/dgrijalva/jwt-go"
	"github.com/gorilla/mux"
	"github.com/jinzhu/gorm"
	_ "github.com/jinzhu/gorm/dialects/postgres"
	"golang.org/x/crypto/bcrypt"
)

//--------GLOBAL VARIABLES---------------

var (
	router      *mux.Router
	secretkey   string = "secretkeyjwt"
	tokenSignIn string
	tmpl        *template.Template
)

//------------STRUCTS---------------------

type User2 struct {
	gorm.Model
	Name     string `json:"name"`
	Email    string `gorm:"unique" json:"email"`
	Password string `json:"password"`
	Role     string `json:"role"`
}

type Authentication struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

type Token struct {
	Role        string `json:"role"`
	Email       string `json:"email"`
	TokenString string `json:"token"`
}

type Error struct {
	IsError bool   `json:"isError"`
	Message string `json:"message"`
}

//-------------DATABASE FUNCTIONS---------------------

//returns database connection
func GetDatabase() *gorm.DB {
	databasename := "mydb"
	database := "postgres"
	databasepassword := "Nam12345"
	databaseurl := "postgres://postgres:" + databasepassword + "@localhost/" + databasename + "?sslmode=disable"

	connection, err := gorm.Open(database, databaseurl)
	if err != nil {
		log.Fatalln("Invalid database url")
	}
	sqldb := connection.DB()

	err = sqldb.Ping()
	if err != nil {
		log.Fatal("Database connected")
	}
	fmt.Println("Database connection successful.")
	return connection
}

//create user table in mydb
func InitialMigration() {
	connection := GetDatabase()
	defer CloseDatabase(connection)
	connection.AutoMigrate(User2{})
}

//closes database connection
func CloseDatabase(connection *gorm.DB) {
	sqldb := connection.DB()
	sqldb.Close()
}

//--------------HELPER FUNCTIONS---------------------

//set error message in Error struct
func SetError(err Error, message string) Error {
	err.IsError = true
	err.Message = message
	return err
}

//take password as input and generate new hash password from it
func GeneratehashPassword(password string) (string, error) {
	bytes, err := bcrypt.GenerateFromPassword([]byte(password), 14)
	return string(bytes), err
}

//compare plain password with hash password
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

//Generate JWT token
func GenerateJWT(email, role string) (string, error) {
	var mySigningKey = []byte(secretkey)
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["authorized"] = true
	claims["email"] = email
	claims["role"] = role
	claims["exp"] = time.Now().Add(time.Minute * 30).Unix()

	tokenString, err := token.SignedString(mySigningKey)
	if err != nil {
		fmt.Errorf("Something went Wrong: %s", err.Error())
		return "", err
	}

	return tokenString, nil
}

//---------------------MIDDLEWARE FUNCTION-----------------------

//check whether user is authorized or not
func IsAuthorized(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {

		r.Header.Set("Token", tokenSignIn)

		if tokenSignIn == "" {
			var err Error
			err = SetError(err, "No Token Found")
			json.NewEncoder(w).Encode(err)
			return
		}

		var mySigningKey = []byte(secretkey)

		token, err := jwt.Parse(r.Header["Token"][0], func(token *jwt.Token) (interface{}, error) {
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("There was an error in parsing token.")
			}
			return mySigningKey, nil
		})

		if err != nil {
			var err Error
			err = SetError(err, "Your Token has been expired.")
			json.NewEncoder(w).Encode(err)
			return
		}

		if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
			if claims["role"] == "admin" {
				r.Header.Set("Role", "admin")
				handler.ServeHTTP(w, r)
				return

			} else if claims["role"] == "user" {
				r.Header.Set("Role", "user")
				handler.ServeHTTP(w, r)
				return

			}
		}
		var reserr Error
		reserr = SetError(reserr, "Not Authorized.")
		json.NewEncoder(w).Encode(err)
	}
}

//----------------------ROUTES-------------------------------
//create a mux router
func CreateRouter() {
	router = mux.NewRouter()
}

//initialize all routes
func InitializeRoute() {
	router.HandleFunc("/signup", SignUpPage).Methods("GET")
	router.HandleFunc("/signin", SignInPage).Methods("GET")
	router.HandleFunc("/signup", SignUp).Methods("POST")
	router.HandleFunc("/signin", SignIn).Methods("POST")
	router.HandleFunc("/admin/signout", IsAuthorized(SignOut)).Methods("POST")
	router.HandleFunc("/admin/delete/{ID}", IsAuthorized(DeleteUser)).Methods("POST")
	router.HandleFunc("/admin", IsAuthorized(AdminIndex)).Methods("GET")
	router.HandleFunc("/user/signout", IsAuthorized(SignOut)).Methods("POST")
	router.HandleFunc("/user", IsAuthorized(UserIndex)).Methods("GET")
	router.HandleFunc("/", Index).Methods("GET")
}

//start the server
func ServerStart() {
	fmt.Println("Server started at http://localhost:8000")
	log.Fatal(http.ListenAndServe(":8000", router))
}

//----------------------ROUTES HANDLER-----------------------
func SignUpPage(w http.ResponseWriter, r *http.Request) {
	tmpl = template.Must(template.ParseFiles("signUp.html"))

	tmpl.Execute(w, nil)
}

func SignUp(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer CloseDatabase(connection)

	var user User2
	var err error

	user.Name = r.FormValue("Name")
	user.Email = r.FormValue("Email")
	user.Role = r.FormValue("Role")
	user.Password, err = GeneratehashPassword(r.FormValue("Password"))

	if err != nil {
		log.Fatalln("Error in hashing password")
	}

	var dbuser User2
	connection.Where("email = ?", user.Email).First(&dbuser)

	//check email is alredy registered or not
	if dbuser.Email != "" {
		var err Error
		err = SetError(err, "Email already in use")

		tmpl = template.Must(template.ParseFiles("signUp.html"))

		tmpl.Execute(w, err)
	} else {
		connection.Create(&user)

		http.Redirect(w, r, "/signin", http.StatusSeeOther)
	}
}

func SignInPage(w http.ResponseWriter, r *http.Request) {
	tmpl = template.Must(template.ParseFiles("signIn.html"))

	tmpl.Execute(w, nil)
}

func SignIn(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer CloseDatabase(connection)

	var authDetails Authentication

	authDetails.Email = r.FormValue("Email")
	authDetails.Password = r.FormValue("Password")

	var authUser User2
	connection.Where("email = 	?", authDetails.Email).First(&authUser)

	if authUser.Email == "" {
		var err Error
		err = SetError(err, "Email is incorrect")

		tmpl = template.Must(template.ParseFiles("signIn.html"))

		tmpl.Execute(w, err)
	} else {
		check := CheckPasswordHash(authDetails.Password, authUser.Password)

		if !check {
			var err Error
			err = SetError(err, "Password is incorrect")

			tmpl = template.Must(template.ParseFiles("signIn.html"))

			tmpl.Execute(w, err)
		}

		validToken, err := GenerateJWT(authUser.Email, authUser.Role)
		if err != nil {
			var err Error
			err = SetError(err, "Failed to generate token")
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(err)
			return
		}

		tokenSignIn = validToken

		var token Token
		token.Email = authUser.Email
		token.Role = authUser.Role
		token.TokenString = validToken
		if authUser.Role == "user" {
			http.Redirect(w, r, "/user", http.StatusSeeOther)
		} else {
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
		}
	}

}

func Index(w http.ResponseWriter, r *http.Request) {
	//w.Write([]byte("HOME PUBLIC INDEX PAGE"))
	http.Redirect(w, r, "/signin", http.StatusSeeOther)
}

func AdminIndex(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Role") != "admin" {
		fmt.Println(r.Header)
		w.Write([]byte("Not authorized."))
		return
	} else {
		connection := GetDatabase()
		defer CloseDatabase(connection)

		var users []User2

		connection.Find(&users)

		type RenderStruct struct {
			Role string
			Data []User2
		}

		var renderStruct = RenderStruct{"admin", users}

		tmpl = template.Must(template.ParseFiles("userManagement.html"))

		tmpl.Execute(w, renderStruct)
	}
	//w.Write([]byte("Welcome, Admin."))
}

func UserIndex(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Role") != "user" {
		fmt.Println(r.Header)
		w.Write([]byte("Not Authorized."))
		return
	} else {
		connection := GetDatabase()
		defer CloseDatabase(connection)

		var users []User2

		connection.Find(&users)

		type RenderStruct struct {
			Role string
			Data []User2
		}

		var renderStruct = RenderStruct{"user", users}

		tmpl = template.Must(template.ParseFiles("userManagement.html"))

		tmpl.Execute(w, renderStruct)
	}
	//w.Write([]byte("Welcome, User."))
}

func DeleteUser(w http.ResponseWriter, r *http.Request) {
	connection := GetDatabase()
	defer CloseDatabase(connection)

	params := mux.Vars(r)
	userId := params["ID"]

	fmt.Println("hello " + userId)

	connection.Delete(&User2{}, userId)

	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func SignOut(w http.ResponseWriter, r *http.Request) {
	tokenSignIn = ""
	http.Redirect(w, r, "/signin", http.StatusSeeOther)
}

func main() {
	InitialMigration()
	CreateRouter()
	InitializeRoute()
	ServerStart()
}
