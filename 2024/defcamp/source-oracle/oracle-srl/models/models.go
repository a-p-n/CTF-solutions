package models

import (
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
)

var DB *gorm.DB

func ConnectDatabase(dsn_url string) {
	dsn := dsn_url
	database, db_err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if db_err != nil {
		panic("Failed to connect to database!")
	}

	database.AutoMigrate(&Product{})
	database.AutoMigrate(&Account{})

	populateDatabase(database)

	DB = database
}
