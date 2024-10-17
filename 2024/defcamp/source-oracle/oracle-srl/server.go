package main

import (
	"gin-mvc/router"
)

func main() {

	// cron := cron.New()
	// cron.AddFunc("0 * * * * *", func() {
	// 	client.CheckProducts()
	// })
	// cron.Start()

	r := router.InitRouter()
	r.Run(":8000")
}
