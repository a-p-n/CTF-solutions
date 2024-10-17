package middlewares

import (
	"fmt"
	"gin-mvc/controllers"
	"gin-mvc/session"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
)

func TestMw() gin.HandlerFunc {
	return func(c *gin.Context) {
		println("Test Middleware " + time.Now().String())
		c.Next()
	}
}

func CheckSess() gin.HandlerFunc {
	return func(c *gin.Context) {
		session_token, err := c.Cookie("session_token")
		if session_token == "" || err != nil {
			c.Set("isLoggedIn", false)
			c.Next()
			return
		}
		fmt.Println(session_token)
		email, err := session.ValidateSessionToken(session_token, controllers.Key)
		fmt.Println(email, err, "aaaa")
		if err != nil {
			c.Redirect(http.StatusFound, "/login?error="+err.Error())
			return
		}
		if email == "" {
			c.Redirect(http.StatusFound, "/login?error=Invalid session token")
			return
		}
		if email != "" {
			c.Set("isLoggedIn", true)
			c.Set("Email", email)
			c.Next()
		} else {
			c.Set("isLoggedIn", false)
			c.Next()
		}
	}
}
