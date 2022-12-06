package models

import (
	"gorm.io/gorm"
)

type DataLock struct {
	gorm.Model

	UserID uint
}

func CreateDataLock(d *DataLock) error {
	err := db.Create(&d).Error
	return err
}

func CountDataLock(userID uint) (uint, error) {
	var count int64
	err := db.Where("user_id = ?", userID).Count(&count).Error
	if err != nil {
		return 0, err
	}
	return uint(count), nil
}

func DeleteDataLock(userID uint) error {
	return db.Where("user_id = ?", userID).Delete(&DataLock{}).Error
}
