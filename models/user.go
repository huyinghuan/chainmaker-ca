package models

import "chainmaker.org/wx-CRA-backend/models/db"

//InsertUser .
func InsertUser(customer *db.User) error {
	if err := db.DB.Debug().Create(customer).Error; err != nil {
		return err
	}
	return nil
}

//UserByNamePwd .
func UserByNamePwd(name, password string) (*db.User, error) {
	var customer db.User
	if err := db.DB.Where("name=? AND password=?", name, password).First(&customer).Error; err != nil {
		return nil, err
	}
	return &customer, nil
}
