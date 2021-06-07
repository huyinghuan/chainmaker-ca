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
--privileged=true \
-p 8090:8090 \
-w /chainmaker-ca \
-v $path/chainmaker-ca:/chainmaker-ca \
--name chainmaker-ca \
--restart always \
ubuntu:18.04 \
bash -c "./chainmaker-ca -config ./conf/config.yaml"
sleep 2s
docker logs chainmaker-ca
echo "chainmaker-ca server start!"