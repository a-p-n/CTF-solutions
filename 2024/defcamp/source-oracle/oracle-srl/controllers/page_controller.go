package controllers

import (
	"crypto/rand"
	"fmt"
	"gin-mvc/models"
	"gin-mvc/session"
	"net/http"

	"github.com/gin-gonic/gin"
	"golang.org/x/crypto/bcrypt"
)

var Key []byte

func init() {
	Key = make([]byte, 16)
	_, err := rand.Read(Key)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Generated key: %x\n", Key)
}

func IndexPage(c *gin.Context) {
	c.HTML(http.StatusOK, "page/index", gin.H{
		"title":      "Oracle SRL - Home",
		"IsLoggedIn": c.GetBool("isLoggedIn"),
	})
}

func ProductsPage(c *gin.Context) {
	products, err := models.FetchProducts(models.DB)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.HTML(http.StatusOK, "page/products", gin.H{
		"title":      "Oracle SRL - Products",
		"IsLoggedIn": c.GetBool("isLoggedIn"),
		"Products":   products,
	})
}

func LoginPage(c *gin.Context) {
	if c.Request.Method == "POST" {
		email := c.PostForm("email")
		password := c.PostForm("password")

		account, err := models.GetAccountByEmail(models.DB, email)
		if err != nil {
			c.Redirect(http.StatusFound, "/login?error=Invalid email or password")
			return
		}

		err = bcrypt.CompareHashAndPassword([]byte(account.Password), []byte(password))
		if err != nil {
			c.Redirect(http.StatusFound, "/login?error=Invalid email or password")
			return
		}

		session_token, err := session.GenerateSessionToken(email, password, Key)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.SetCookie("session_token", session_token, 3600, "/", c.Request.Host, false, false)

		c.Redirect(http.StatusFound, "/")
		return
	} else if c.Request.Method == "GET" {

		message := c.Query("message")
		errror := c.Query("error")
		c.HTML(http.StatusOK, "page/login", gin.H{
			"title":      "Oracle SRL - Login",
			"message":    message,
			"error":      errror,
			"isLoggedIn": false,
		})

	}
}

func RegisterPage(c *gin.Context) {
	if c.Request.Method == "POST" {
		name := c.PostForm("name")
		email := c.PostForm("email")
		password := c.PostForm("password")

		hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		account := models.Account{Name: name, Email: email, Password: string(hashedPassword)}

		err = models.CreateAccount(models.DB, &account)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create account"})
			return
		}

		c.Redirect(http.StatusSeeOther, "/login?message=Registration successful, please login")

	} else if c.Request.Method == "GET" {
		c.HTML(http.StatusOK, "page/register", gin.H{
			"title":      "Oracle SRL - Register",
			"isLoggedIn": false,
		})
	}
}

func ProfilePage(c *gin.Context) {

	email := c.GetString("Email")
	account, err := models.GetAccountByEmail(models.DB, email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.HTML(http.StatusOK, "page/profile", gin.H{
		"title":      "Oracle SRL - Profile",
		"IsLoggedIn": c.GetBool("isLoggedIn"),
		"Username":   account.Name,
		"Email":      account.Email,
		"JoinedDate": account.CreatedAt.Format("2006-01-02"),
	})
}
