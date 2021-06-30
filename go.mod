module chainmaker.org/chainmaker-ca-backend

go 1.15

require (
	chainmaker.org/chainmaker-go/common v0.0.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gin-gonic/gin v1.6.3
	github.com/spf13/viper v1.7.1
	github.com/tjfoc/gmsm v1.3.2
	go.uber.org/zap v1.16.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
	gorm.io/driver/mysql v1.1.0
	gorm.io/gorm v1.21.11
)

replace chainmaker.org/chainmaker-go/common => ./src/common