package models

import (
	"time"

	"gorm.io/gorm"
)

type Product struct {
	gorm.Model
	ID          uint       `gorm:"primaryKey;autoIncrement"`
	Name        string     `gorm:"not null;size:255"`
	Description *string    `gorm:"size:255"`
	ImageURL    *string    `gorm:"size:255"`
	Price       *string    `gorm:"size:255"`
	CreatedAt   time.Time  `gorm:"autoCreateTime"`
	UpdatedAt   time.Time  `gorm:"autoCreateTime;autoUpdateTime"`
	DeletedAt   *time.Time `gorm:"index"`
}

func FetchProducts(db *gorm.DB) ([]Product, error) {
	var products []Product
	if err := db.Find(&products).Error; err != nil {
		return nil, err
	}
	return products, nil
}

func CreateProduct(db *gorm.DB, product *Product) error {
	if err := db.Create(product).Error; err != nil {
		return err
	}
	return nil
}

func DeleteProduct(db *gorm.DB, id string) error {
	if err := db.Where("id = ?", id).Delete(&Product{}).Error; err != nil {
		return err
	}
	return nil
}
