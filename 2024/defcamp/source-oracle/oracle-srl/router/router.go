package router

import (
	"gin-mvc/controllers"
	"gin-mvc/middlewares"
	"gin-mvc/models"

	"html/template"
	"log"
	"os"

	"github.com/foolin/goview"
	"github.com/foolin/goview/supports/ginview"
	"github.com/gin-gonic/gin"
	"github.com/joho/godotenv"
)

func InitRouter() *gin.Engine {

	err := godotenv.Load()
	if err != nil {
		log.Fatal("Error loading .env file")
	}

	models.ConnectDatabase(os.Getenv("DB_CONN_URL"))

	r := gin.Default()

	r.Static("/static", "./static")

	r.HTMLRender = ginview.New(goview.Config{
		Root:      "views",
		Extension: ".html",
		Master:    "layouts/master",
		Partials:  []string{},
		Funcs: template.FuncMap{
			"safe": func(s string) template.HTML {
				return template.HTML(s)
			},
		},
	})

	r.Use(middlewares.CSPMiddleware())

	r.GET("/", middlewares.CheckSess(), controllers.IndexPage)
	r.GET("/products", middlewares.CheckSess(), controllers.ProductsPage)
	r.GET("/profile", middlewares.CheckSess(), controllers.ProfilePage)
	r.GET("/login", controllers.LoginPage)
	r.POST("/login", controllers.LoginPage)
	r.GET("/register", controllers.RegisterPage)
	r.POST("/register", controllers.RegisterPage)

	api := r.Group("/api")
	{
		api.POST("/addProduct", controllers.AddProduct)
		api.GET("/getProducts", controllers.GetProducts)
		api.GET("/deleteProduct/:id", controllers.DeleteProduct)
	}

	return r
}
