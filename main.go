package main

import (
	"log"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
)

var users = map[string][]string{
	"durvesh.danve@veritas.com": {"Google", "Microsoft", "Okta"},
	"default":                   {"Google", "Okta"},
}

func getOAuthProviders(c *gin.Context) {
	username := c.Query("username")
	providers, exists := users[username]
	if !exists {
		providers = users["default"]
	}
	c.JSON(http.StatusOK, gin.H{"providers": providers})
}

func main() {
	r := gin.Default()

	r.Use(cors.New(cors.Config{
		AllowOrigins:     []string{"http://localhost:4200"},
		AllowMethods:     []string{"GET", "POST", "OPTIONS"},
		AllowHeaders:     []string{"Content-Type"},
		AllowCredentials: true,
	}))

	r.GET("/api/oauth-providers", getOAuthProviders)

	err := r.Run(":8080")
	if err != nil {
		log.Fatalf("Server failed: %s", err)
	}
}
