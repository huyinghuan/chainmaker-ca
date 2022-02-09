# CA证书服务

## 功能介绍

1. 根据提供的信息生成公私钥和签发单个证书，并保存证书和密钥（root密钥不作保存，只生成文件）。
2. 通过CSR文件签发单个证书，并保存证书。
3. 可以延期某个具体证书的有效期。
4. 可以通过证书链上的CA证书撤销某个证书。
5. 能够生成CA证书的最新的撤销列表文件（CRL文件）。
6. root证书可以选择配置或者自签生成。
7. 可以配置不同的启动方式，用来区分tls和sign证书的签发。
8. 可以签发单独使用的tls加密或者签名证书（国密标准，tls双证书）。
9. 可以配置中间证书启动，保护root证书。
10. 提供开启密钥文件加密功能。



## 安装部署

#### 环境依赖

* golang
  * 版本为1.17或以上
  * 下载地址：https://golang.org/dl/
* mysql
  * 版本8.0及以上
  * 下载地址：https://dev.mysql.com/downloads/installer/

### 代码下载

```sh
$ git clone --rescursive git@github.com:huyinghuan/chainmaker-ca.git
cd chainmaker-ca
git submodule init && git submodule update
```

源地址为：`https://git.chainmaker.org.cn/chainmaker/chainmaker-ca.git`

### 运行启动

```sh
$ cd src/
$ go build -o chainmaker-ca
$ ./chainmaker-ca
```

vscode运行: 打开`启动调试即可`

现在可通过配置的端口访问服务接口：

例如：http://localhost:8090/test

如果看到“Hello,World!”字样代表服务启动。

### docker 部署

直接打包编译完成后的 二进制文件即可

## 配置文件详解

配置文件使用了 `go 1.17`的`go:embed` 特性，将配置文件打包进了二进制执行文件

目录：默认为测试环境
正式环境为: ```src/conf/asserts/config.yaml``` 
测试环境为: ```src/conf/asserts/config.dev.yaml```

可以通过设置环境变量 `RUN_MODE='product'` 切换配置到正式配置。
或者通过编译时制定编译参数: `-ldflags="-X 'chainmaker.org/chainmaker-ca-backend/conf.RunMode=product'"` 来制定正式配置

配置文件主要是以下几部分构成：

### base config

CA服务的基础配置

```yaml
# Base config
base_config:
  server_port: 8090                     #服务端口
  ca_type: double_root                  #启动模式：double_root/single_root/tls/sign
  expire_year: 2                        #签发有效年限
  hash_type: SHA256                     #使用哈希类型：SHA256/SHA3_256/SM3
  key_type: ECC_NISTP256                #使用密钥类型：ECC_NISTP256/SM2
  can_issue_ca: true                    #是否能继续签发CA证书          
  provide_service_for: [org1,org2]      #提供服务的组织列表   
  key_encrypt: false                    #密钥是否加密 
  access_control: true                  #是否开启访问控制
```

***注**

* SM2和SM3必须要搭配使用



* **ca_type:**

  CA启动模式，可以将tls和sign证书签发服务分离部署。

  - tls，该服务只提供为tls证书的签发服务。

  - sign，该服务只提供sign证书的签发服务。

  - single_root，可以为tls和sign证书同时提供签发服务，使用一个root CA证书。

  - double_root，可以为tls和sign证书同时提供签发服务，使用两个root CA证书。

* **can_issue_ca:**

  在所提供服务的组织内，是否能够签发中间CA证书。

* **provide_service_for:**

  对列表中的组织提供签发服务。可以仅配置一个组织，只为单个提供服务。也可以配置多个，向多个组织提供签发服务。

* **key_encrypt:**

  提供密钥文件加密的开关。如果开启，密钥会采用PEMCipherAES256加密方式，加密密钥文件。（root密钥不存储，也不加密）

* **access_control:**

  访问控制开关，如果开启，访问将服务的所有接口需要携带token访问。

### root config

root 证书的路径和CSR配置

```yaml
# Root CA config
root_config:
  cert:
    -
      cert_type: tls                                             #root证书的类型：tls/sign
      cert_path: ../crypto-config/rootCA/tls/root-tls.crt        #证书的路径     
      private_key_path: ../crypto-config/rootCA/tls/root-tls.key #密钥的路径  
    -
      cert_type: sign
      cert_path: ../crypto-config/rootCA/sign/root-sign.crt               
      private_key_path: ../crypto-config/rootCA/sign/root-sign.key       
  csr:
    CN: root.org-wx                                              #证书的信息的CN字段
    O: org-wx                                                    #证书的信息的O字段
    OU: root                                                     #证书的信息的OU字段
    country: CN                                                  #证书的信息的country字段
    locality: Beijing                                            #证书的信息的locality字段
    province: Beijing                                            #证书的信息的province字段
```

* **cert_type:**

  证书的路径类型，如果CA的启动方式是double_root，需要同时配置tls和sign两种类型的证书路径。如果CA启动方式是single_root，需要配置sign类型的证书路径。

* **csr（选填）:**

  * 不填：读取cert目录下的root证书启动服务。

  * 填写：以CSR配置自签root证书启动服务。

  其中，OU字段需要符合chainmaker的证书校验规范，否则链上会校验失败。需要填写root。

### intermediate_config

**可选配置**

中间CA的生成配置

```yaml
# intermediate config
intermediate_config:                 
  -
    csr:
      CN: ca.org1
      O: org1
      OU: ca
      country: CN
      locality: Beijing
      province: Beijing
    private_key_pwd: wx123
  -
    csr:
      CN: ca.org2
      O: org2
      OU: ca
      country: CN
      locality: Beijing
      province: Beijing
    private_key_pwd: wx123
```

### access_control_config

**可选配置**

访问控制账号配置

```yaml
access_control_config:
  -
    app_role: admin            #角色
    app_id: admin              #账户ID
    app_key: passw0rd          #账户口令
  - 
    app_role: user
    app_id: user1
    app_key: passw0rd
```

* **app_role**  
  * admin : 所有权限
  * user ：不能进行吊销、延期证书。只能申请，查询证书。

### database config（MySQL）

数据库信息配置

```yaml
db_config:
  user: root                   #用户名
  password: 123456             #密码
  ip: 127.0.0.1                #数据库服务器的IP地址
  port: 3306                   #数据库服务器的端口号
  dbname: chainmaker_ca        #建立的数据库的名称
```

### log config

日志相关配置

```yaml
log_config: 
  level: error               #日志等级
  filename: ../log/ca.log    #日志存取路径
  max_size: 1                #在进行切割之前，日志文件的最大大小（以MB为单位）
  max_age: 30                #保留旧文件的最大天数
  max_backups: 5             #保留旧文件的最大个数
```



## 可部署方式

![CA-deployment.png](./img/CA-deployment.png)

### 配置文件的使用

**集中式1：**

1. 属于集中式部署，为多个组织提供服务，base_config.provide_service_for需要配置多个组织。

2. 启用多个中间CA，intermediate_config需要配置多个。

3. 不允许继续签发中间CA证书，base_config.can_issue_ca为false。

**集中式2：**

1. 属于集中式部署，为多个组织提供服务，base_config.provide_service_for需要配置多个组织。

2. 启用单个中间CA证书，intermediate_config需要配置一个。

3. 不允许继续签发中间CA证书，base_config.can_issue_ca为false。

**分布式1：**

属于分布式和集中混合部署方式

* 集中式部分

1. 为多个组织提供服务，base_config.provide_service_for需要配置多个组织。

2. 没有启用配置中间CA证书，intermediate_config不需要配置。

3. 允许继续签发中间CA证书，base_config.can_issue_ca为ture。

* 分布式部分：

1. 为一个组织提供服务，base_config.provide_service_for需要配置单个组织。

2. root证书选择配置启动，root_config.csr部分不需要配置。

3. 没有启用配置中间CA证书，intermediate_config不需要配置。

4. 不允许继续签发中间CA证书，base_config.can_issue_ca为false。

**分布式2：**

1. 属于分布式部署，为单个组织提供服务，base_config.provide_service_for只需要配置一个组织。

2. 启用配置一个中间CA证书，intermediate_config需要配置一个。

3. 不允许继续签发中间CA证书，base_config.can_issue_ca为false。



## 服务接口

### Code与Msg

| Code |                     Msg                     |     含义     |
| :--: | :-----------------------------------------: | :----------: |
| 200  |  The request service returned successfully  |     成功     |
| 202  |         Missing required parameters         | 输入参数缺失 |
| 204  |  There is an error in the input parameter   | 输入参数非法 |
| 500  | An error occurred with the internal service | 执行服务失败 |

### 传参方式

统一为request body JSON的形式。

### 登录获取token接口

请求地址：http://localhost:8090/api/ca/login

请求方式：POST

请求参数：

|  字段  |  类型  |   含义   | 备注 |
| :----: | :----: | :------: | :--: |
| appId  | string |  登录id  | 必填 |
| appKey | string | 登录口令 | 必填 |

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": {
        "accessToken": "1111111",
        "expiressIn": 7200
    }
}
```

|    字段     |  类型  |      含义      |
| :---------: | :----: | :------------: |
| accessToken | string |    token值     |
| expiressIn  | number | 过期时间（秒） |

### 申请证书

从创建密钥对到证书，一步完成。

请求URL：http://localhost:8090/api/ca/gencert

请求方式：POST

请求参数：

|     字段      |  类型  |       含义       | 备注  |
| :-----------: | :----: | :--------------: | :---: |
|     orgId     | string |      组织ID      | 必填  |
|    userId     | string |      用户ID      | *选填 |
|   userType    | string |     用户类型     | 必填  |
|   certUsage   | string |     证书用途     | 必填  |
| privateKeyPwd | string |     密钥密码     | 选填  |
|    country    | string | 证书字段（国家） | 必填  |
|   locality    | string | 证书字段（城市） | 必填  |
|   province    | string | 证书字段（省份） | 必填  |
|     token     | string |      token       | 选填  |

* userType: 1.root , 2.ca , 3.admin , 4.client , 5.consensus , 6.common

* certUsage: 1.sign , 2.tls , 3.tls-sign , 4.tls-enc

*注：

* userId 只有在申请的用户类型是ca的类型时，可以填写为空。在申请节点证书时，需要保证链上节点ID唯一。

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": {
        "cert": "-----BEGIN CERTIFICATE-----\nMIICRTCCAeygAwIBAgIIHRMopTJcqQYwCgYIKoZIzj0EAwIwXzELMAkGA1UEBhMC\nQ04xEDAOBgNVBAgTB0JlaWppbmcxEDAOBgNVBAcTB0JlaWppbmcxDTALBgNVBAoT\nBG9yZzExCzAJBgNVBAsTAmNhMRAwDgYDVQQDEwdjYS5vcmc4MB4XDTIxMDYxMTA5\nMTgwNloXDTIzMDYxMTA5MTgwNlowYzEOMAwGA1UEBhMFY2hpbmExEDAOBgNVBAgT\nB2JlaWppbmcxEDAOBgNVBAcTB2hhaWRpYW4xDTALBgNVBAoTBG9yZzExDjAMBgNV\nBAsTBWFkbWluMQ4wDAYDVQQDEwV1c2VyMjBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABAKZjYa/bYc9Vp6eNJHRp5AwYTZxj2e5HLDAuuJkW4c53V8D/Tl/VWMKi70E\nOpUZMXoLhMBFhQrQn8Ydcl8kyECjgY0wgYowDgYDVR0PAQH/BAQDAgP4MBMGA1Ud\nJQQMMAoGCCsGAQUFBwMCMCkGA1UdDgQiBCAKiUV2poJIpNQT5Xpusdm+boynJ3kS\nzOtCTrIOD0Ox6TArBgNVHSMEJDAigCDJC+s7sFB6/d9DFghQiuhBwXsduZYUz8Ds\nqjYS272EIzALBgNVHREEBDACggAwCgYIKoZIzj0EAwIDRwAwRAIgCQmmzIuIKMH+\nc6BpZWBNtZqSWCuQpkwBtgJR09M/Z8cCICdZCyKrKuEAcHaVC9CeJVK4yXE/44Vt\nKrfKbpmDyMBp\n-----END CERTIFICATE-----\n",
        "privateKey": "-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEILHD/QaWovCdBtUnxgMGJrN63A6ZsLen/dCRYLhrvJ+/oAoGCCqGSM49\nAwEHoUQDQgAEApmNhr9thz1Wnp40kdGnkDBhNnGPZ7kcsMC64mRbhzndXwP9OX9V\nYwqLvQQ6lRkxeguEwEWFCtCfxh1yXyTIQA==\n-----END EC PRIVATE KEY-----\n"
    }
}
```

| 字段       | 类型   | 含义     | 备注 |
| ---------- | ------ | -------- | ---- |
| cert       | string | 证书内容 |      |
| privateKey | string | 密钥内容 |      |

### 申请CSR

请求URL： http://localhost:8090/api/ca/gencsr

请求方式：POST

请求参数：

|     字段      |  类型  |       含义       | 备注  |
| :-----------: | :----: | :--------------: | :---: |
|     orgId     | string |      组织ID      | 必填  |
|    userId     | string |      用户ID      | *选填 |
|   userType    | string |     用户类型     | 必填  |
| privateKeyPwd | string |     密钥密码     | 选填  |
|    country    | string | 证书字段（国家） | 必填  |
|   locality    | string | 证书字段（城市） | 必填  |
|   province    | string | 证书字段（省份） | 必填  |
|     token     | string |      token       | *选填 |

* userType: 1.root , 2.ca , 3.admin , 4.client , 5.consensus , 6.common

*注：

* userId 只有在申请的用户类型是ca的类型时，可以填写为空。在申请节点证书时，需要保证链上节点ID唯一。

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": "-----BEGIN CERTIFICATE REQUEST-----\nMIIBHjCBxQIBADBjMQ4wDAYDVQQGEwVjaGluYTEQMA4GA1UECBMHYmVpamluZzEQ\nMA4GA1UEBxMHaGFpZGlhbjENMAsGA1UEChMEb3JnNzEOMAwGA1UECxMFYWRtaW4x\nDjAMBgNVBAMTBXVzZXIyMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEaRv9OA2Z\nm/GcJibe/77u8lpABOLOVGgHzAzOd/h+9+Kq4+46CjXaISxEeTrqEMhLKCjcM1Bb\nm8jF5rWiQCFKFaAAMAoGCCqGSM49BAMCA0gAMEUCIFYjsphgIcInLjdhyYtILnFR\nJH7T/vahNbut8OvEgQ9tAiEAsNxL8xw+hGfhd9NgrxEx3Fv9Vj6wv1X3jaHvljME\n76U=\n-----END CERTIFICATE REQUEST-----\n"
}
```

### 通过CSR申请证书

请求URL：http://localhost:8090/api/ca/gencertbycsr

请求方式：POST

请求参数：

|   字段    |  类型  |   含义    | 备注  |
| :-------: | :----: | :-------: | :---: |
|   orgId   | string |  组织ID   | 必填  |
|  userId   | string |  用户ID   | *选填 |
| userType  | string | 用户类型  | 必填  |
| certUsage | string | 证书用途  | 必填  |
|    csr    | string | csr文件流 | 必填  |
|   token   | string |   token   | 选填  |

* userType: 1.root , 2.ca , 3.admin , 4.client , 5.consensus , 6.common
* certUsage: 1.sign , 2.tls , 3.tls-sign , 4.tls-enc

*注：

* userId 只有在申请的用户类型是ca的类型时，可以填写为空。在申请节点证书时，需要保证链上节点ID唯一。

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": "-----BEGIN CERTIFICATE-----\nMIICRjCCAeygAwIBAgIIOpUpifGOIq8wCgYIKoZIzj0EAwIwXzELMAkGA1UEBhMC\nQ04xEDAOBgNVBAgTB0JlaWppbmcxEDAOBgNVBAcTB0JlaWppbmcxDTALBgNVBAoT\nBG9yZzExCzAJBgNVBAsTAmNhMRAwDgYDVQQDEwdjYS5vcmc4MB4XDTIxMDYxMTA5\nMjkzNloXDTIzMDYxMTA5MjkzNlowYzEOMAwGA1UEBhMFY2hpbmExEDAOBgNVBAgT\nB2JlaWppbmcxEDAOBgNVBAcTB2hhaWRpYW4xDTALBgNVBAoTBG9yZzcxDjAMBgNV\nBAsTBWFkbWluMQ4wDAYDVQQDEwV1c2VyMjBZMBMGByqGSM49AgEGCCqGSM49AwEH\nA0IABGkb/TgNmZvxnCYm3v++7vJaQATizlRoB8wMznf4fvfiquPuOgo12iEsRHk6\n6hDISygo3DNQW5vIxea1okAhShWjgY0wgYowDgYDVR0PAQH/BAQDAgP4MBMGA1Ud\nJQQMMAoGCCsGAQUFBwMCMCkGA1UdDgQiBCCmG5dsVApdmQpESV7gmSAMXgjTsAUK\n/rCwty3HET9TxTArBgNVHSMEJDAigCDJC+s7sFB6/d9DFghQiuhBwXsduZYUz8Ds\nqjYS272EIzALBgNVHREEBDACggAwCgYIKoZIzj0EAwIDSAAwRQIgP3KOsh0H9Va1\nuQnpj1Q05A1irOHctTzPCff6emMPNwgCIQDLmpEcXWfUojrse2qaMPe21zMs/XWC\nsH7vBuVuzY2PtA==\n-----END CERTIFICATE-----\n"
}
```

### 多条件查询证书

请求URL：http://localhost:8090/api/ca/querycerts

请求方式：POST

请求参数：

|   字段    |  类型  |   含义   | 备注 |
| :-------: | :----: | :------: | :--: |
|   orgId   | string |  组织ID  | 选填 |
|  userId   | string |  用户ID  | 选填 |
| userType  | string | 用户类型 | 选填 |
| certUsage | string | 证书用途 | 选填 |
|   token   | string |  token   | 选填 |

* userType: 1.root , 2.ca , 3.admin , 4.client , 5.consensus , 6.common
* certUsage: 1.sign , 2.tls , 3.tls-sign , 4.tls-enc

返回数据：

```json
{
	"code": 200,
    "msg": "The request service returned successfully",
    "data": [
        {
            "userId": "user1",
            "orgId": "org1",
            "userType": "admin",
            "certUsage": "tls-enc",
            "certSn": 2723312771322077578,
            "issuerSn":3450584804990292327,
            "certContent": "-----BEGIN CERTIFICATE-----\nMIICSDCCAe+gAwIBAgIINZ4eqVdx6XMwCgYIKoZIzj0EAwIwXzELMAkGA1UEBhMC\nQ04xEDAOBgNVBAgTB0JlaWppbmcxEDAOBgNVBAcTB0JlaWppbmcxDTALBgNVBAoT\nBG9yZzExCzAJBgNVBAsTAmNhMRAwDgYDVQQDEwdjYS5vcmc4MB4XDTIxMDYxMTA5\nMzE1MFoXDTI1MDYxMDA5MzE1MFowZjEOMAwGA1UEBhMFY2hpbmExEDAOBgNVBAgT\nB2JlaWppbmcxEDAOBgNVBAcTB2hhaWRpYW4xDTALBgNVBAoTBG9yZzExDzANBgNV\nBAsTBmNsaWVudDEQMA4GA1UEAxMHdXNlcjExMTBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPISUU2pW5fqKWHpFoqFPWjnqivLZfHXQrSHEwRL94ay91m1m91/TOfe\n9lVpcrCvoCwBP4wukI57ih8bd+p9QPijgY0wgYowDgYDVR0PAQH/BAQDAgP4MBMG\nA1UdJQQMMAoGCCsGAQUFBwMCMCkGA1UdDgQiBCB73+mPJoYO3KbqHKZnccbQhgIO\nlrqWf6ZtHh+lGX5yVjArBgNVHSMEJDAigCDJC+s7sFB6/d9DFghQiuhBwXsduZYU\nz8DsqjYS272EIzALBgNVHREEBDACggAwCgYIKoZIzj0EAwIDRwAwRAIgLND6yzE/\nHVs9DYLMLcSq4STiri4k/KhMwneErZDd4PACIGPQEgKf0DtSJvZ4bMMUrCuenjjD\nSKoDGSKdDIxWNaw1\n-----END CERTIFICATE-----\n",
            "expirationDate": 1685695242
        },
        {
            "userId": "user1",
            "orgId": "org1",
            "userType": "admin",
            "certUsage": "tls-enc",
            "certSn": 3450584804990292327,
            "issuerSn":3450584804990292327,
            "certContent": "-----BEGIN CERTIFICATE-----\nMIICSDCCAe+gAwIBAgIINZ4eqVdx6XMwCgYIKoZIzj0EAwIwXzELMAkGA1UEBhMC\nQ04xEDAOBgNVBAgTB0JlaWppbmcxEDAOBgNVBAcTB0JlaWppbmcxDTALBgNVBAoT\nBG9yZzExCzAJBgNVBAsTAmNhMRAwDgYDVQQDEwdjYS5vcmc4MB4XDTIxMDYxMTA5\nMzE1MFoXDTI1MDYxMDA5MzE1MFowZjEOMAwGA1UEBhMFY2hpbmExEDAOBgNVBAgT\nB2JlaWppbmcxEDAOBgNVBAcTB2hhaWRpYW4xDTALBgNVBAoTBG9yZzExDzANBgNV\nBAsTBmNsaWVudDEQMA4GA1UEAxMHdXNlcjExMTBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPISUU2pW5fqKWHpFoqFPWjnqivLZfHXQrSHEwRL94ay91m1m91/TOfe\n9lVpcrCvoCwBP4wukI57ih8bd+p9QPijgY0wgYowDgYDVR0PAQH/BAQDAgP4MBMG\nA1UdJQQMMAoGCCsGAQUFBwMCMCkGA1UdDgQiBCB73+mPJoYO3KbqHKZnccbQhgIO\nlrqWf6ZtHh+lGX5yVjArBgNVHSMEJDAigCDJC+s7sFB6/d9DFghQiuhBwXsduZYU\nz8DsqjYS272EIzALBgNVHREEBDACggAwCgYIKoZIzj0EAwIDRwAwRAIgLND6yzE/\nHVs9DYLMLcSq4STiri4k/KhMwneErZDd4PACIGPQEgKf0DtSJvZ4bMMUrCuenjjD\nSKoDGSKdDIxWNaw1\n-----END CERTIFICATE-----\n",
            "expirationDate": 1685695408
        }
    ]
}
```

|      字段      |  类型  |       含义       |    备注    |
| :------------: | :----: | :--------------: | :--------: |
|     certSn     | int64  |    证书序列号    |            |
|    issuerSn    | int64  | 签发者证书序列号 |            |
|  certContent   | string |     证书内容     |            |
|     userId     | string |      用户ID      |            |
|     orgId      | string |      组织ID      |            |
|    userType    | string |     用户类型     |            |
|   certUsage    | string |     证书用途     |            |
| expirationDate | int64  |     到期时间     | unix时间戳 |

### 延期证书

请求URL：http://localhost:8090/api/ca/renewcert

请求方式：POST

请求参数：

|  字段  |  类型  |    含义    | 备注 |
| :----: | :----: | :--------: | :--: |
| certSn | number | 证书序列号 | 必填 |
| token  | string |   token    | 选填 |

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": "-----BEGIN CERTIFICATE-----\nMIICSDCCAe+gAwIBAgIINZ4eqVdx6XMwCgYIKoZIzj0EAwIwXzELMAkGA1UEBhMC\nQ04xEDAOBgNVBAgTB0JlaWppbmcxEDAOBgNVBAcTB0JlaWppbmcxDTALBgNVBAoT\nBG9yZzExCzAJBgNVBAsTAmNhMRAwDgYDVQQDEwdjYS5vcmc4MB4XDTIxMDYxMTA5\nMzE1MFoXDTI1MDYxMDA5MzE1MFowZjEOMAwGA1UEBhMFY2hpbmExEDAOBgNVBAgT\nB2JlaWppbmcxEDAOBgNVBAcTB2hhaWRpYW4xDTALBgNVBAoTBG9yZzExDzANBgNV\nBAsTBmNsaWVudDEQMA4GA1UEAxMHdXNlcjExMTBZMBMGByqGSM49AgEGCCqGSM49\nAwEHA0IABPISUU2pW5fqKWHpFoqFPWjnqivLZfHXQrSHEwRL94ay91m1m91/TOfe\n9lVpcrCvoCwBP4wukI57ih8bd+p9QPijgY0wgYowDgYDVR0PAQH/BAQDAgP4MBMG\nA1UdJQQMMAoGCCsGAQUFBwMCMCkGA1UdDgQiBCB73+mPJoYO3KbqHKZnccbQhgIO\nlrqWf6ZtHh+lGX5yVjArBgNVHSMEJDAigCDJC+s7sFB6/d9DFghQiuhBwXsduZYU\nz8DsqjYS272EIzALBgNVHREEBDACggAwCgYIKoZIzj0EAwIDRwAwRAIgLND6yzE/\nHVs9DYLMLcSq4STiri4k/KhMwneErZDd4PACIGPQEgKf0DtSJvZ4bMMUrCuenjjD\nSKoDGSKdDIxWNaw1\n-----END CERTIFICATE-----\n"
}
```

### 撤销证书

请求URL：http://localhost:8090/api/ca/revokecert

请求方式：POST

请求参数：

|     字段      |  类型  |          含义          | 备注 |
| :-----------: | :----: | :--------------------: | :--: |
| revokedCertSn | number |       证书序列号       | 必填 |
| issuerCertSn  | number | 撤销者（ca）证书序列号 | 必填 |
|    reason     | string |        撤销原因        | 选填 |
|     token     | string |         token          | 选填 |

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": "-----BEGIN CRL-----\nMIIBNTCB3AIBATAKBggqhkjOPQQDAjBfMQswCQYDVQQGEwJDTjEQMA4GA1UECBMH\nQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzENMAsGA1UEChMEb3JnMTELMAkGA1UE\nCxMCY2ExEDAOBgNVBAMTB2NhLm9yZzgXDTIxMDYxMTA5NTQ0M1oXDTIxMDYxMTEw\nNTQ0M1owGzAZAggdEyilMlypBhcNMjMwNjExMDkxODA2WqAvMC0wKwYDVR0jBCQw\nIoAgyQvrO7BQev3fQxYIUIroQcF7HbmWFM/A7Ko2Etu9hCMwCgYIKoZIzj0EAwID\nSAAwRQIgFslGwq9Bb9a4wrOSatqRwRu9E0QMmCavrgr6GQRn5fcCIQDCV8mAepI9\nDLEbHtDHqzJ/CrGcRMJWL3gYzBNhWE/yLQ==\n-----END CRL-----\n"
}
```

### 获取某个CA的最新的撤销列表

请求URL：http://localhost:8090/api/ca/gencrl

请求方式：POST

请求参数：

|     字段     |  类型  |     含义     | 备注 |
| :----------: | :----: | :----------: | :--: |
| issuerCertSn | number | CA证书序列号 | 必填 |
|    token     | string |    token     | 选填 |

返回数据：

```json
{
    "code": 200,
    "msg": "The request service returned successfully",
    "data": "-----BEGIN CRL-----\nMIIBNTCB3AIBATAKBggqhkjOPQQDAjBfMQswCQYDVQQGEwJDTjEQMA4GA1UECBMH\nQmVpamluZzEQMA4GA1UEBxMHQmVpamluZzENMAsGA1UEChMEb3JnMTELMAkGA1UE\nCxMCY2ExEDAOBgNVBAMTB2NhLm9yZzgXDTIxMDYxMTA5NTQ0M1oXDTIxMDYxMTEw\nNTQ0M1owGzAZAggdEyilMlypBhcNMjMwNjExMDkxODA2WqAvMC0wKwYDVR0jBCQw\nIoAgyQvrO7BQev3fQxYIUIroQcF7HbmWFM/A7Ko2Etu9hCMwCgYIKoZIzj0EAwID\nSAAwRQIgFslGwq9Bb9a4wrOSatqRwRu9E0QMmCavrgr6GQRn5fcCIQDCV8mAepI9\nDLEbHtDHqzJ/CrGcRMJWL3gYzBNhWE/yLQ==\n-----END CRL-----\n"
}
```



