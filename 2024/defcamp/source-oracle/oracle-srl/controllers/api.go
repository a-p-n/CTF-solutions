package controllers

import (
	"encoding/json"
	"gin-mvc/models"
	"net/http"

	"github.com/gin-gonic/gin"
)

func AddProduct(c *gin.Context) {
	if isAdmin() {
		decoder := json.NewDecoder(c.Request.Body)

		var product models.Product

		if err := decoder.Decode(&product); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request payload"})
			return
		}

		err := models.CreateProduct(models.DB, &product)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusCreated, gin.H{"status": "Product created successfully"})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not authorized to add a product"})
		return
	}
}

func GetProducts(c *gin.Context) {
	if isAdmin() {
		products, err := models.FetchProducts(models.DB)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, products)
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not authorized to view the products"})
		return
	}
}

func DeleteProduct(c *gin.Context) {
	if isAdmin() {
		id := c.Param("id")

		err := models.DeleteProduct(models.DB, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
			return
		}

		c.JSON(http.StatusOK, gin.H{"status": "Product deleted successfully"})
	} else {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "You are not authorized to delete the product"})
	}
}

func isAdmin() bool {
	return true
}
