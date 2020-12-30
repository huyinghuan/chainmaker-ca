module chainmaker.org/wx-CRA-backend

go 1.15

require (
	chainmaker.org/chainmaker-go/common v0.0.0
	github.com/gin-gonic/gin v1.6.3
	github.com/jinzhu/gorm v1.9.16
	github.com/spf13/viper v1.7.1
	go.uber.org/zap v1.16.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace chainmaker.org/chainmaker-go/common => ./common
