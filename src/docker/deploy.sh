#!/bin/bash
path=`pwd`
docker run -d \
-p 8090:8090 \
-w /chainmaker-ca \
-v $path/chainmaker-ca:/chainmaker-ca \
--name chainmaker-ca \
--restart always \
ubuntu:18.04 \
bash -c "./chainmaker-ca -config ./config.yaml"