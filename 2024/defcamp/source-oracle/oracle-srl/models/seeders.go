package models

import (
	"gorm.io/gorm"
)

func populateDatabase(db *gorm.DB) {
	products := []Product{
		{Name: "Mystical Spellbook", Description: stringPtr("A comprehensive guide to powerful spells and rituals."), ImageURL: stringPtr("https://i.etsystatic.com/6707552/r/il/e43614/4185954018/il_fullxfull.4185954018_2ou0.jpg"), Price: stringPtr("100$")},
		{Name: "Enchanted Charm", Description: stringPtr("A charm infused with powerful protective magic."), ImageURL: stringPtr("https://m.media-amazon.com/images/I/81qIFt46YpL._AC_UY1000_.jpg"), Price: stringPtr("69$")},
		{Name: "Mystical Amulet", Description: stringPtr("An amulet that grants enhanced spiritual energy."), ImageURL: stringPtr("https://img.freepik.com/premium-photo/isolated-mystic-eye-amulet-mystical-symbol-themed-pendant-made-bro-clipart-game-asset-concept_655090-1200776.jpg"), Price: stringPtr("1$")},
		{Name: "Voodoo Doll", Description: stringPtr("A traditional voodoo doll for various rituals and spells."), ImageURL: stringPtr("https://www.snugzy.com/cdn/shop/products/Snugzy-Voodoo-Doll.jpg?v=1571674895"), Price: stringPtr("1111$")},
	}

	for _, product := range products {
		db.Create(&product)
	}
}

func stringPtr(s string) *string {
	return &s
}
