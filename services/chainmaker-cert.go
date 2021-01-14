package services

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"path"
	"path/filepath"

	"chainmaker.org/chainmaker-go/common/crypto"
	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/models/db"
	"chainmaker.org/wx-CRA-backend/utils"
	"go.uber.org/zap"
)

//GenerateChainMakerCert 生成chainmaker全套证书
func GenerateChainMakerCert(cmCertApplyReq *models.ChainMakerCertApplyReq) error {
	//首先每个组织是root签发的一个中间CA
	//循环签发出中间CA
	if cmCertApplyReq.ChainID == "" {
		err := fmt.Errorf("chainId can't be empty")
		logger.Error("Generate chainmaker cert failed!", zap.Error(err))
		return err
	}
	if cmCertApplyReq.Orgs == nil {
		err := fmt.Errorf("orgs can't be empty")
		logger.Error("Generate chainmaker cert failed!", zap.Error(err))
		return err
	}
	for _, org := range cmCertApplyReq.Orgs {
		//生成公私钥
		//暂时采用不加密方式（调用不加密接口）
		privateKey, keyID, err := CreateUserKeyPair(org.UserID)
		if err != nil {
			logger.Error("Create ChainMaker org keypair failed!", zap.Error(err))
			return err
		}
		//生成中间证书的CSR
		CN := "ca." + org.CommonName
		csrBytes, err := createCSR(privateKey, org.Country, org.Locality, org.Province, org.OrganizationalUnit,
			org.Organization, CN)
		if err != nil {
			logger.Error("Create ChainMaker org CSR failed!", zap.Error(err))
			return err
		}
		//读取配置文件里的根证书
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		issuerPrivKeyFilePath, certFilePath := utils.GetRootPrivateKey()
		privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
		if err != nil {
			logger.Error("Read private key file failed!", zap.Error(err))
			return err
		}
		//私钥解密
		issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetRootCaPrivateKeyPwd(), hashType)
		if err != nil {
			logger.Error("Decrypt private key  failed!", zap.Error(err))
			return err
		}
		//读取根证书
		certBytes, err := ioutil.ReadFile(certFilePath)
		if err != nil {
			logger.Error("Read cert file failed!", zap.Error(err))
			return err
		}

		//签发中间CA证书
		certModel, err := IssueCertificate(hashType, db.INTERMRDIARY_CA, issuerPrivKey, csrBytes, certBytes, defaultExpireYear, nil, "")
		if err != nil {
			logger.Error("Issue Cert failed!", zap.Error(err))
			return err
		}
		certModel.UserID = org.UserID
		certModel.CertStatus = db.EFFECTIVE
		certModel.CertUsage = db.SIGN
		certModel.PrivateKeyID = keyID
		//证书入库
		err = models.InsertCert(certModel)
		if err != nil {
			logger.Error("Insert cert to db failed!", zap.Error(err))
			return err
		}
		//签发节点sign证书
		err = IssueNodeCert(cmCertApplyReq.ChainID, &org, &privateKey, certModel.Content, db.SIGN)
		if err != nil {
			logger.Error("Issue node sign cert failed!", zap.Error(err))
			return err
		}
		//签发节点TLS证书
		err = IssueNodeCert(cmCertApplyReq.ChainID, &org, &privateKey, certModel.Content, db.TLS)
		if err != nil {
			logger.Error("Issue node tls cert failed!", zap.Error(err))
			return err
		}
		//签发admin证书（使用ca用户）
		err = IssueAdminCert(cmCertApplyReq.ChainID, &org, hashType, privateKey, keyID, certModel.Content, db.SIGN)
		if err != nil {
			logger.Error("Issue admin sign cert failed!", zap.Error(err))
			return err
		}
		//签发admin tls证书（使用ca用户）
		err = IssueAdminCert(cmCertApplyReq.ChainID, &org, hashType, privateKey, keyID, certModel.Content, db.TLS)
		if err != nil {
			logger.Error("Issue admin tls cert failed!", zap.Error(err))
			return err
		}
	}
	err := WriteChainMakerCertFile(cmCertApplyReq)
	if err != nil {
		logger.Error("Write chainmaker cert file failed!", zap.Error(err))
		return err
	}
	return nil
}

//IssueNodeCert 签发节点证书
func IssueNodeCert(chainID string, org *models.Org, privateKey *crypto.PrivateKey, certBytes []byte, certUsage db.CertUsage) error {
	for _, node := range org.Nodes {
		//生成公私钥
		privateKey, keyID, err := CreateUserKeyPair(org.UserID)
		if err != nil {
			return err
		}
		//生成CSR
		OU := node.NodeName
		CN := node.NodeName + "." + db.CertUsage2NameMap[certUsage] + "." + org.Organization
		csrBytes, err := createCSR(privateKey, org.Country, org.Locality, org.Province, OU,
			org.Organization, CN)
		if err != nil {
			return err
		}
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		certModel, err := IssueCertificate(hashType, db.NODE, privateKey, csrBytes, certBytes, utils.GetIssureExpirationTime(), node.Sans, "")
		if err != nil {
			return err
		}
		certModel.ChainID = chainID
		certModel.UserID = org.UserID
		certModel.CertStatus = db.EFFECTIVE
		certModel.CertUsage = certUsage
		certModel.PrivateKeyID = keyID
		certModel.NodeName = node.NodeName
		err = models.InsertCert(certModel)
		if err != nil {
			return err
		}
	}
	return nil
}

//IssueAdminCert .
func IssueAdminCert(chainID string, org *models.Org, hashType crypto.HashType, caPrivKey crypto.PrivateKey, caKeyID string, caCertBytes []byte, certUsage db.CertUsage) error {
	OU := "admin"
	CN := OU + "." + db.CertUsage2NameMap[certUsage] + "." + org.Organization
	csrBytes, err := createCSR(caPrivKey, org.Country, org.Locality, org.Province, OU,
		org.Organization, CN)
	if err != nil {
		return err
	}
	adminCert, err := IssueCertificate(hashType, db.CUSTOMER_ADMIN, caPrivKey, csrBytes, caCertBytes, utils.GetIssureExpirationTime(), nil, "")
	adminCert.UserID = org.UserID
	adminCert.CertStatus = db.EFFECTIVE
	adminCert.CertUsage = certUsage
	adminCert.PrivateKeyID = caKeyID
	adminCert.ChainID = chainID
	//证书入库
	err = models.InsertCert(adminCert)
	if err != nil {
		logger.Error("Insert cert to db failed!", zap.Error(err))
		return err
	}
	return nil
}

//WriteChainMakerCertFile 写证书文件
func WriteChainMakerCertFile(req *models.ChainMakerCertApplyReq) error {
	certBasePath := utils.GetChainMakerCertPath()
	for _, org := range req.Orgs {
		orgPath := filepath.Join(certBasePath, org.CommonName)
		err := WriteCaCertFile(orgPath, &org)
		if err != nil {
			return err
		}
		err = WriteNodeCertFile(orgPath, &org, req.ChainID)
		if err != nil {
			return err
		}
		err = WriteUserCertFile(orgPath, &org, req.ChainID)
		if err != nil {
			return err
		}
	}
	return nil
}

//GetChainMakerCertTar 获取证书压缩包
func GetChainMakerCertTar(filetarget string) ([]byte, error) {
	certBasePath := utils.GetChainMakerCertPath()
	filesource := certBasePath
	err := Tar(filetarget, filesource)
	if err != nil {
		logger.Error("Tar chainmaker file failed!", zap.Error(err))
		return nil, err
	}
	dataBytes, err := ioutil.ReadFile(filetarget)
	if err != nil {
		logger.Error("Read tar file failed!", zap.Error(err))
		return nil, err
	}
	return dataBytes, nil
}

//WriteNodeCertFile .
func WriteNodeCertFile(orgPath string, org *models.Org, chainID string) error {
	for _, node := range org.Nodes {
		nodePath := filepath.Join(orgPath, "node", node.NodeName)
		err := CreateDir(nodePath)
		if err != nil {
			return err
		}
		nodeSignCert, err := models.GetCertByNodeNameUsage(node.NodeName, db.SIGN, chainID)
		if err != nil {
			return err
		}
		nodeTLSCert, err := models.GetCertByNodeNameUsage(node.NodeName, db.TLS, chainID)
		if err != nil {
			return err
		}
		nodeSignKey, err := models.GetKeyPairByID(nodeSignCert.PrivateKeyID)
		if err != nil {
			return err
		}
		nodeTLSKey, err := models.GetKeyPairByID(nodeTLSCert.PrivateKeyID)
		if err != nil {
			return err
		}
		nodeSignCertPath := filepath.Join(nodePath, node.NodeName+".sign.crt")
		err = ioutil.WriteFile(nodeSignCertPath, nodeSignCert.Content, os.ModePerm)
		if err != nil {
			return err
		}
		nodeSignKeyPath := filepath.Join(nodePath, node.NodeName+".sign.key")
		err = ioutil.WriteFile(nodeSignKeyPath, nodeSignKey.PrivateKey, os.ModePerm)
		if err != nil {
			return err
		}
		nodeTLSCertPath := filepath.Join(nodePath, node.NodeName+".tls.crt")
		err = ioutil.WriteFile(nodeTLSCertPath, nodeTLSCert.Content, os.ModePerm)
		if err != nil {
			return err
		}
		nodeTLSKeyPath := filepath.Join(nodePath, node.NodeName+".tls.key")
		err = ioutil.WriteFile(nodeTLSKeyPath, nodeTLSKey.PrivateKey, os.ModePerm)
		if err != nil {
			return err
		}
	}
	return nil
}

//WriteCaCertFile .
func WriteCaCertFile(orgPath string, org *models.Org) error {
	caCert, err := models.GetCertByUserType(org.UserID, db.INTERMRDIARY_CA)
	if err != nil {
		return err
	}
	caPrivate, err := models.GetKeyPairByID(caCert.PrivateKeyID)
	caPath := filepath.Join(orgPath, "ca")
	caCertPath := filepath.Join(caPath, "ca.crt")
	caKeyPath := filepath.Join(caPath, "ca.key")
	if err := CreateDir(caPath); err != nil {
		return err
	}
	err = ioutil.WriteFile(caCertPath, caCert.Content, os.ModePerm)
	if err != nil {
		return err
	}
	err = ioutil.WriteFile(caKeyPath, caPrivate.PrivateKey, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

//WriteUserCertFile .
func WriteUserCertFile(orgPath string, org *models.Org, chainID string) error {
	userCertPath := filepath.Join(orgPath, "user", "admin")
	err := CreateDir(userCertPath)
	if err != nil {
		return err
	}
	userSignCert, err := models.GetCertByUserTypeChain(org.UserID, db.CUSTOMER_ADMIN, db.SIGN, chainID)
	if err != nil {
		return err
	}
	userSignKey, err := models.GetKeyPairByID(userSignCert.PrivateKeyID)
	if err != nil {
		return err
	}
	userTLSCert, err := models.GetCertByUserTypeChain(org.UserID, db.CUSTOMER_ADMIN, db.TLS, chainID)
	if err != nil {
		return err
	}
	userTLSKey, err := models.GetKeyPairByID(userTLSCert.PrivateKeyID)
	if err != nil {
		return err
	}
	userSignCertPath := filepath.Join(userCertPath, "admin.sign.crt")
	err = ioutil.WriteFile(userSignCertPath, userSignCert.Content, os.ModePerm)
	if err != nil {
		return err
	}
	userSignKeyPath := filepath.Join(userCertPath, "admin.sign.key")
	err = ioutil.WriteFile(userSignKeyPath, userSignKey.PrivateKey, os.ModePerm)
	if err != nil {
		return err
	}
	userTLSCertPath := filepath.Join(userCertPath, "admin.tls.crt")
	err = ioutil.WriteFile(userTLSCertPath, userTLSCert.Content, os.ModePerm)
	if err != nil {
		return err
	}
	userTLSKeyPath := filepath.Join(userCertPath, "admin.tls.key")
	err = ioutil.WriteFile(userTLSKeyPath, userTLSKey.PrivateKey, os.ModePerm)
	if err != nil {
		return err
	}
	return nil
}

//Tar .gz
func Tar(filetarget, filesource string) (err error) {
	fw, err := os.Create(filetarget)
	if err != nil {
		if os.IsExist(err) {
			os.RemoveAll(filetarget)
		} else {
			return err
		}
	}
	defer fw.Close()
	gw := gzip.NewWriter(fw)
	defer gw.Close()
	// 创建 tar.Writer，执行打包操作
	tw := tar.NewWriter(fw)
	defer func() {
		// 这里要判断 tw 是否关闭成功，如果关闭失败，则 .tar 文件可能不完整
		if er := tw.Close(); er != nil {
			err = er
		}
	}()

	// 获取文件或目录信息
	fi, err := os.Stat(filesource)
	if err != nil {
		return err
	}

	// 获取要打包的文件或目录的所在位置和名称
	srcBase, srcRelative := path.Split(path.Clean(filesource))

	// 开始打包
	if fi.IsDir() {
		tarDir(srcBase, srcRelative, tw, fi)
	} else {
		tarFile(srcBase, srcRelative, tw, fi)
	}

	return nil
}

// 因为要执行遍历操作，所以要单独创建一个函数
func tarDir(srcBase, srcRelative string, tw *tar.Writer, fi os.FileInfo) (err error) {
	// 获取完整路径
	srcFull := srcBase + srcRelative

	// 在结尾添加 "/"
	last := len(srcRelative) - 1
	if srcRelative[last] != os.PathSeparator {
		srcRelative += string(os.PathSeparator)
	}

	// 获取 srcFull 下的文件或子目录列表
	fis, er := ioutil.ReadDir(srcFull)
	if er != nil {
		return er
	}

	// 开始遍历
	for _, fi := range fis {
		if fi.IsDir() {
			tarDir(srcBase, srcRelative+fi.Name(), tw, fi)
		} else {
			tarFile(srcBase, srcRelative+fi.Name(), tw, fi)
		}
	}

	// 写入目录信息
	if len(srcRelative) > 0 {
		hdr, er := tar.FileInfoHeader(fi, "")
		if er != nil {
			return er
		}
		hdr.Name = srcRelative

		if er = tw.WriteHeader(hdr); er != nil {
			return er
		}
	}

	return nil
}

// 因为要在 defer 中关闭文件，所以要单独创建一个函数
func tarFile(srcBase, srcRelative string, tw *tar.Writer, fi os.FileInfo) (err error) {
	// 获取完整路径
	srcFull := srcBase + srcRelative

	// 写入文件信息
	hdr, er := tar.FileInfoHeader(fi, "")
	if er != nil {
		return er
	}
	hdr.Name = srcRelative

	if er = tw.WriteHeader(hdr); er != nil {
		return er
	}

	// 打开要打包的文件，准备读取
	fr, er := os.Open(srcFull)
	if er != nil {
		return er
	}
	defer fr.Close()

	// 将文件数据写入 tw 中
	if _, er = io.Copy(tw, fr); er != nil {
		return er
	}
	return nil
}
