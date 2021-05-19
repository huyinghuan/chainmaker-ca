module chainmaker.org/chainmaker-ca-backend

go 1.15

require (
	chainmaker.org/chainmaker-go/common v0.0.0
	github.com/gin-gonic/gin v1.6.3
	github.com/jinzhu/gorm v1.9.16
	github.com/satori/go.uuid v1.2.0
	github.com/spf13/viper v1.7.1
	github.com/stretchr/testify v1.6.1
	github.com/tjfoc/gmsm v1.3.2
	go.uber.org/zap v1.16.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gorm.io/driver/mysql v1.1.0
	gorm.io/gorm v1.21.10
)

replace chainmaker.org/chainmaker-go/common => ./src/common
