FROM golang:1.16 as builder
ENV GOPROXY=https://goproxy.cn,direct
COPY . /chainmaker-ca-backend
RUN cd /chainmaker-ca-backend/src && go build

# the second stage
FROM ubuntu
WORKDIR /chainmaker-ca-backend
COPY --from=builder /chainmaker-ca-backend/src/src ./chainmaker_ca
# COPY ./src/conf ./conf

CMD ./chainmaker_ca -config ./conf/config.yaml