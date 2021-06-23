/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package db

import (
	"fmt"
	"log"
	"os"
	"time"

	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
	"gorm.io/gorm/schema"
)

//DB database
var DB *gorm.DB

//DB init
func DBInit() {
	var err error
	newLogger := logger.New(
		log.New(os.Stdout, "\r\n", log.LstdFlags), // io writer
		logger.Config{
			SlowThreshold:             time.Second,   // Slow SQL threshold
			LogLevel:                  logger.Silent, // Log level
			IgnoreRecordNotFoundError: true,          // Ignore ErrRecordNotFound error for logger
			Colorful:                  false,         // Disable color
		},
	)
	DB, err = gorm.Open(mysql.New(mysql.Config{
		DSN:                       utils.GetDBConfig(),
		DefaultStringSize:         256,   // The default length of a field of type string
		DisableDatetimePrecision:  true,  // Disable datetime accuracy, which is not supported by databases prior to MySQL 5.6
		DontSupportRenameIndex:    true,  // When renaming an index, drop and create a new one. Databases prior to MySQL 5.7 and MariaDB do not support renaming indexes
		DontSupportRenameColumn:   true,  // Use 'change' to rename columns. Prior to MySQL 8, databases and MariaDB do not support renaming columns
		SkipInitializeWithVersion: false, // Automatically configured according to the current MySQL version
	}), &gorm.Config{
		Logger: newLogger,
		NamingStrategy: schema.NamingStrategy{
			SingularTable: true,
		},
	})
	if err != nil {
		err = fmt.Errorf("[DB] gorm open mysql failed: %s", err.Error())
		panic(err)
	}
	sqlDB, err := DB.DB()
	if err != nil {
		err = fmt.Errorf("[DB] gorm connect the pool failed: %s", err.Error())
		panic(err)
	}
	sqlDB.SetMaxIdleConns(10)
	sqlDB.SetMaxOpenConns(100)
	sqlDB.SetConnMaxLifetime(time.Minute)
	// Set table options
	DB.Set("gorm:association_autoupdate", false).Set("gorm:association_autocreate", false).Set("gorm:table_options", "ENGINE=InnoDB")
	err = DB.Set("gorm:table_options", "CHARSET=utf8").Set("gorm:table_options", "COLLATE=utf8_general_ci").AutoMigrate(
		&CertContent{},
		&CertInfo{},
		&KeyPair{},
		&RevokedCert{},
		&AppInfo{},
	)
	if err != nil {
		err = fmt.Errorf("[DB] create table failed: %s", err.Error())
		panic(err)
	}
}
