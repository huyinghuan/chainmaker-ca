#!/bin/bash
path=`pwd`

echo "start mysql service..."
docker run -d \
    -p 13306:3306 \
    -e MYSQL_ROOT_PASSWORD=123456 \
    -e MYSQL_DATABASE=chainmaker_ca \
    --name ca-mysql \
    --restart always \
    mysql:8.0
echo "waiting for database initialization..."
sleep 12s
docker logs --tail=10 ca-mysql

echo "start ca services..."
docker run -d \
-p 8090:8090 \
-w /chainmaker-ca \
-v $path/chainmaker-ca:/chainmaker-ca \
-v $path/log:/log \
-v $path/crypto-config:/crypto-config \
-u root \
--privileged=true \
--name ca-server \
--restart always \
ubuntu:18.04 \
bash -c "./chainmaker-ca -config ./conf/config.yaml"
sleep 2s
docker logs ca-server
echo "chainmaker-ca server start!"