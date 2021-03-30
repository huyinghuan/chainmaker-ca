package db

import (
	"time"

	"chainmaker.org/chainmaker-ca-backend/src/loggers"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"github.com/jinzhu/gorm"
	"go.uber.org/zap"
)

var log *zap.Logger

//DB 数据库db
var DB *gorm.DB

//GormErrRNF .
var GormErrRNF = gorm.ErrRecordNotFound

// GormLogger struct
type GormLogger struct{}

// Print - Log Formatter
func (*GormLogger) Print(v ...interface{}) {
	switch v[0] {
	case "sql":
		log.Debug(
			"sql",
			zap.String("module", "gorm"),
			zap.String("type", "sql"),
			zap.Any("src", v[1]),
			zap.Any("duration", v[2]),
			zap.Any("sql", v[3]),
			zap.Any("values", v[4]),
			zap.Any("rows_returned", v[5]),
		)
	case "log":
		log.Debug("log", zap.Any("gorm", v[2]))
	}
}

//InitDB .
func InitDB() {
	var err error
	DB, err = gorm.Open("mysql", utils.GetDBConfig())
	if err != nil {
		panic(err)
	}
	log = loggers.GetLogger()
	gormLogger := &GormLogger{}
	DB.SetLogger(gormLogger)
	DB.LogMode(true)
	DB.DB().SetMaxIdleConns(50)
	DB.DB().SetMaxOpenConns(50)
	DB.DB().SetConnMaxLifetime(time.Minute)
	DB.Set("gorm:association_autoupdate", false).Set("gorm:association_autocreate", false)
	DB.SingularTable(true)
	err = DB.AutoMigrate(
		&Cert{},
		&KeyPair{},
		&RevokedCert{},
		&NodeId{},
	).Error
	if err != nil {
		log.Error("Create table failed!", zap.Error(err))
	}
}
