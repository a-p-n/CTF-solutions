package models

import (
	"time"

	"gorm.io/gorm"
)

type Account struct {
	gorm.Model
	ID        uint       `gorm:"primaryKey;autoIncrement"`
	Name      string     `gorm:"not null;size:255"`
	Email     string     `gorm:"not null;unique;size:255"`
	Password  string     `gorm:"not null;size:255"`
	CreatedAt time.Time  `gorm:"autoCreateTime"`
	UpdatedAt time.Time  `gorm:"autoCreateTime;autoUpdateTime"`
	DeletedAt *time.Time `gorm:"index"`
}

func CreateAccount(db *gorm.DB, account *Account) error {
	return db.Create(account).Error
}

func GetAccountByEmail(db *gorm.DB, email string) (*Account, error) {
	var account Account
	if err := db.Where("email = ?", email).First(&account).Error; err != nil {
		return nil, err
	}
	return &account, nil
}

func DeleteAccount(db *gorm.DB, account *Account) error {
	return db.Delete(account).Error
}
