package models

import "chainmaker.org/wx-CRA-backend/models/db"

//InsertCustomer .
func InsertCustomer(customer *db.Customer) error {
	if err := db.DB.Debug().Create(customer).Error; err != nil {
		return err
	}
	return nil
}

//CustomerByNamePwd .
func CustomerByNamePwd(name, password string) (*db.Customer, error) {
	var customer db.Customer
	if err := db.DB.Where("name=? AND password=?", name, password).First(&customer).Error; err != nil {
		return nil, err
	}
	return &customer, nil
}

//GetCustomerIDByName .
func GetCustomerIDByName(name string) (id int, err error) {
	var customer db.Customer
	if err = db.DB.Table(customer.TableName()).Where("name=?", name).First(&customer).Error; err != nil {
		return id, err
	}
	id = customer.ID
	return
}
