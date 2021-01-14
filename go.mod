module chainmaker.org/wx-CRA-backend

go 1.15

require (
	chainmaker.org/chainmaker-go/common v0.0.0
	github.com/dgrijalva/jwt-go v3.2.0+incompatible
	github.com/gin-gonic/gin v1.6.3
	github.com/golang/protobuf v1.4.1
	github.com/jinzhu/gorm v1.9.16
	github.com/satori/go.uuid v1.2.0
	github.com/spf13/viper v1.7.1
	go.uber.org/zap v1.16.0
	google.golang.org/grpc v1.32.0
	google.golang.org/protobuf v1.25.0
	gopkg.in/natefinch/lumberjack.v2 v2.0.0
)

replace chainmaker.org/chainmaker-go/common => ./common
