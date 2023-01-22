package main

import (
	"context"
	"html/template"
	"log"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/gorilla/mux"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/bson/primitive"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"golang.org/x/crypto/bcrypt"
)

type User struct {
	ID       primitive.ObjectID `json:"_id" bson:"_id,omitempty"`
	Name     string             `json:"name" bson:"name,omitempty"`
	Email    string             `json:"email" bson:"email,omitempty"`
	Password string             `json:"password" bson:"password,omitempty"`
	Gender   string             `json:"gender" bson:"gender,omitempty"`
}

func getUser(w http.ResponseWriter, r *http.Request, collection *mongo.Collection) {
	// parse template
	tmpl, _ := template.ParseFiles("templates/index.html")
	// execute the template
	tmpl.Execute(w, nil)
}
func postUser(w http.ResponseWriter, r *http.Request, collection *mongo.Collection) {
	// Decode the form data
	user := &User{
		Name:     r.FormValue("name"),
		Email:    r.FormValue("email"),
		Password: r.FormValue("password"),
		Gender:   r.FormValue("gender"),
	}

	// Hash the password
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(user.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatal(err)
	}
	user.Password = string(hashedPassword)

	// Insert the data into MongoDB
	user.ID = primitive.NewObjectID()
	_, err = collection.InsertOne(context.TODO(), user)

	if err != nil {
		log.Fatal(err)
	}
	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func login(w http.ResponseWriter, r *http.Request, collection *mongo.Collection) {
	//parse the login template
	tmpl, _ := template.ParseFiles("templates/login.html")
	//execute the template
	tmpl.Execute(w, nil)
}

func handleLogin(w http.ResponseWriter, r *http.Request, collection *mongo.Collection) {
	// Log the request details
	log.Println("Received login request")

	if r.Method != http.MethodPost {
		http.Error(w, "Invalid request method", http.StatusMethodNotAllowed)
		return
	}
	r.ParseForm()
	email := r.FormValue("email")
	password := r.FormValue("password")
	log.Println("Email: ", email)
	log.Println("Password: ", password)

	//check if the email and password match
	var user User
	err := collection.FindOne(context.TODO(), bson.M{"email": email}).Decode(&user)
	if err != nil {
		log.Println("Error finding user: ", err)
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Compare the password with the hashed password
	err = bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password))
	if err != nil {
		log.Println("Error comparing password: ", err)
		http.Error(w, "Invalid email or password", http.StatusUnauthorized)
		return
	}

	// Create JWT token
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email":  user.Email,
		"name":   user.Name,
		"gender": user.Gender,
	})

	// Sign and get the complete encoded token as a string
	tokenString, err := token.SignedString([]byte("secret"))
	if err != nil {
		http.Error(w, "Error creating JWT token", http.StatusInternalServerError)
		return
	}

	// Set the JWT token in the cookie
	http.SetCookie(w, &http.Cookie{
		Name:    "jwt",
		Value:   tokenString,
		Expires: time.Now().Add(time.Hour * 24),
	})

	// Redirect the user to the profile page
	http.Redirect(w, r, "/profile", http.StatusSeeOther)
}

func profile(w http.ResponseWriter, r *http.Request, collection *mongo.Collection) {
	// Get the JWT token from the cookie
	cookie, err := r.Cookie("jwt")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	// Verify the JWT token
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		// Get the user information from the JWT claims
		user := &User{
			Email:  claims["email"].(string),
			Name:   claims["name"].(string),
			Gender: claims["gender"].(string),
		}

		//parse the profile template
		tmpl, _ := template.ParseFiles("templates/profile.html")
		//execute the template and pass the user data
		tmpl.Execute(w, user)
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}
func updateUser(w http.ResponseWriter, r *http.Request, collection *mongo.Collection) {
	// Get the user's ID from the JWT token
	cookie, err := r.Cookie("jwt")
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	token, err := jwt.Parse(cookie.Value, func(token *jwt.Token) (interface{}, error) {
		return []byte("secret"), nil
	})
	if err != nil {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		email := claims["email"].(string)

		// Update the user's information in MongoDB
		update := bson.M{
			"$set": bson.M{
				"name":   r.FormValue("name"),
				"gender": r.FormValue("gender"),
			},
		}
		_, err = collection.UpdateOne(context.TODO(), bson.M{"email": email}, update)
		if err != nil {
			log.Fatal(err)
		}
		http.Redirect(w, r, "/notice", http.StatusMovedPermanently)
	} else {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
	}
}

func noticeHandler(w http.ResponseWriter, r *http.Request) {
	tmpl := template.Must(template.ParseFiles("templates/notice.html"))
	err := tmpl.Execute(w, nil)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	// Connect to MongoDB
	client, err := mongo.NewClient(options.Client().ApplyURI("mongodb://localhost:27017"))
	if err != nil {
		log.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	err = client.Connect(ctx)
	if err != nil {
		log.Fatal(err)
	}

	collection := client.Database("mydb").Collection("users")

	// Initialize the router
	router := mux.NewRouter()

	// Handle routes
	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		getUser(w, r, collection)
	}).Methods("GET")

	router.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		postUser(w, r, collection)
	}).Methods("POST")

	router.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		login(w, r, collection)
	}).Methods("GET")

	router.HandleFunc("/handlelogin", func(w http.ResponseWriter, r *http.Request) {
		handleLogin(w, r, collection)
	}).Methods("POST")

	router.HandleFunc("/profile", func(w http.ResponseWriter, r *http.Request) {
		profile(w, r, collection)
	}).Methods("GET")

	router.HandleFunc("/update", func(w http.ResponseWriter, r *http.Request) {
		updateUser(w, r, collection)
	}).Methods("POST")
	router.HandleFunc("/notice", noticeHandler)

	// Start the server
	http.ListenAndServe(":8080", router)
}
