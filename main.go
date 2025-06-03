package main

import (
	"embed"
	"encoding/gob"
	"fmt"
	"html/template"
	"net/http"
	"os"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/glebarez/sqlite"
	"github.com/gorilla/sessions"
	"github.com/joho/godotenv"
	"github.com/markbates/goth"
	"github.com/markbates/goth/gothic"
	"github.com/markbates/goth/providers/github"
	"gorm.io/gorm"
)

// Embed static and template files
//
//go:embed static/*
var static embed.FS

//go:embed templates/*
var templates embed.FS

// User struct for database
type User struct {
	Name          string
	SocialCredits int
}

// Initialize gob for session serialization
func init() {
	gob.Register(map[string]interface{}{})
}

// Load environment variables
func loadEnv() {
	if err := godotenv.Load(); err != nil {
		fmt.Println("Error loading .env file")
	}
}

// Initialize database
func initDB() *gorm.DB {
	db, err := gorm.Open(sqlite.Open("socialcred.db"), &gorm.Config{})
	if err != nil {
		panic("failed to connect database")
	}
	db.AutoMigrate(&User{})
	return db
}

// Configure session store
func initSessionStore() *sessions.CookieStore {
	store := sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))
	store.Options = &sessions.Options{
		Path:     "/",
		HttpOnly: true,
		Secure:   os.Getenv("GIN_MODE") == "release", // Secure should be false in development
	}
	gothic.Store = store
	return store
}

// Middleware to check if user is logged in
func requireLogin(store *sessions.CookieStore) gin.HandlerFunc {
	return func(c *gin.Context) {
		session, err := store.Get(c.Request, "gothic_session") // Use "gothic_session" consistently
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve session: " + err.Error()})
			c.Abort()
			return
		}

		userEmail, ok := session.Values["user_email"].(string)
		if !ok || userEmail == "" {
			c.JSON(http.StatusForbidden, gin.H{"error": "You must be logged in to access this page.", "email": userEmail})
			c.Abort()
			return
		}

		c.Set("user_email", userEmail)
		c.Next()
	}
}

func main() {
	// Load environment variables
	loadEnv()

	// Initialize database
	db := initDB()

	// Set up goth for authentication
	goth.UseProviders(github.New(
		os.Getenv("GITHUB_CLIENT_ID"),
		os.Getenv("GITHUB_CLIENT_SECRET"),
		os.Getenv("HOST")+"/auth/callback",
		"read:user", "user:email"),
	)

	motd := ""

	// Initialize session store
	store := initSessionStore()

	// Initialize Gin router
	r := gin.Default()

	r.SetHTMLTemplate(template.Must(template.New("").ParseFS(templates, "templates/*")))

	r.StaticFS("/f", http.FS(static))

	// Webpage routes
	r.GET("/", func(c *gin.Context) {
		var users []User
		// Fetch users and score from db in descending order of SocialCredits
		db.Order("social_credits DESC").Find(&users)
		c.HTML(http.StatusOK, "index.html", gin.H{
			"title": "SocialCred",
			"users": users,
			"motd":  motd,
		})
	})

	r.GET("/admin", requireLogin(store), func(c *gin.Context) {
		userEmail := c.GetString("user_email")
		var users []User
		db.Order("social_credits DESC").Find(&users)
		c.HTML(http.StatusOK, "admin.html", gin.H{
			"title": "Admin Panel",
			"email": userEmail,
			"users": users,
			"motd":  motd,
		})
	})

	// Authentication routes
	r.GET("/auth", func(c *gin.Context) {
		q := c.Request.URL.Query()
		q.Add("provider", "github")
		c.Request.URL.RawQuery = q.Encode()
		gothic.BeginAuthHandler(c.Writer, c.Request)
	})

	r.GET("/auth/callback", func(c *gin.Context) {
		q := c.Request.URL.Query()
		q.Add("provider", "github")
		c.Request.URL.RawQuery = q.Encode()
		user, err := gothic.CompleteUserAuth(c.Writer, c.Request)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to complete user authentication: " + err.Error()})
			return
		}

		allowedEmails := os.Getenv("ALLOWED_EMAILS")
		if allowedEmails != "" {
			emails := make(map[string]bool)
			for _, email := range strings.Split(allowedEmails, ",") {
				emails[email] = true
			}
			if !emails[user.Email] {
				c.JSON(http.StatusForbidden, gin.H{"error": "You are not allowed to access this application."})
				return
			}
		}

		session, err := store.Get(c.Request, "gothic_session") // Use "gothic_session" consistently
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve session: " + err.Error()})
			return
		}

		session.Values["user_email"] = user.Email
		if err := store.Save(c.Request, c.Writer, session); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session: " + err.Error()})
			return
		}

		c.Redirect(http.StatusPermanentRedirect, "/admin")
	})

	r.GET("/logout", func(c *gin.Context) {
		gothic.Logout(c.Writer, c.Request)
		session, err := store.Get(c.Request, "gothic_session") // Use "gothic_session" consistently
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve session: " + err.Error()})
			return
		}
		delete(session.Values, "user_email")
		if err := store.Save(c.Request, c.Writer, session); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to save session: " + err.Error()})
			return
		}
		c.Redirect(http.StatusSeeOther, "/")
	})

	// Functionality routes
	r.POST("/update", requireLogin(store), func(c *gin.Context) {
		var payload struct {
			Name          string `json:"name"`
			SocialCredits string `json:"socialCredits"` // Accept as string from JSON
		}

		if err := c.BindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Convert SocialCredits to integer
		socialCredits, err := strconv.Atoi(payload.SocialCredits)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "SocialCredits must be a valid integer"})
			return
		}

		// Update the user in the database
		if err := db.Model(&User{}).Where("name = ?", payload.Name).Update("social_credits", socialCredits).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update Social Credits"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	r.POST("/add", requireLogin(store), func(c *gin.Context) {
		var payload struct {
			Name          string `json:"name"`
			SocialCredits string `json:"socialCredits"`
		}

		if err := c.BindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		// Validate Name
		if payload.Name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Name cannot be empty"})
			return
		}

		// Convert SocialCredits to integer
		socialCredits, err := strconv.Atoi(payload.SocialCredits)
		if err != nil || socialCredits < 0 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "SocialCredits must be a valid positive integer"})
			return
		}

		// Add the new user to the database
		newUser := User{Name: payload.Name, SocialCredits: socialCredits}
		if err := db.Create(&newUser).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to add new user"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	r.POST("/delete", requireLogin(store), func(c *gin.Context) {
		var payload struct {
			Name string `json:"name"`
		}
		if err := c.BindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}
		if payload.Name == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Name cannot be empty"})
			return
		}
		// Delete the user from the database
		if err := db.Where("name = ?", payload.Name).Delete(&User{}).Error; err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete user"})
			return
		}
		c.JSON(http.StatusOK, gin.H{"success": true})
	})

	r.POST("/motd", requireLogin(store), func(c *gin.Context) {
		var payload struct {
			Message string `json:"message"`
		}
		if err := c.BindJSON(&payload); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}
		motd = payload.Message
		c.JSON(http.StatusOK, gin.H{"success": true, "message": motd})
	})

	// Start the server on port 8080
	if err := r.Run(":8080"); err != nil {
		fmt.Println("Failed to start server:", err)
		os.Exit(1)
	}
}
