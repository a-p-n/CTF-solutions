package middlewares

import (
	"fmt"
	"gin-mvc/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

func CSPMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		products, err := models.FetchProducts(models.DB)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			c.Abort()
			return
		}
		csp := "default-src 'self'; script-src 'self' https://trusted.cdn.com; style-src 'self' https://trusted.cdn.com; img-src 'self' "
		for _, product := range products {
			fmt.Println(*product.ImageURL)
			csp += *product.ImageURL + " "
		}

		c.Header("Content-Security-Policy", csp)
		c.Next()
	}
}
