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
func GenerateChainMakerCert(cmCertApplyReq *models.ChainMakerCertApplyReq) (string, error) {
	//首先每个组织是root签发的一个中间CA
	//循环签发出中间CA
	var filepath string
	if cmCertApplyReq.ChainID == "" {
		err := fmt.Errorf("chainId can't be empty")
		logger.Error("Generate chainmaker cert failed!", zap.Error(err))
		return filepath, err
	}
	if cmCertApplyReq.Orgs == nil {
		err := fmt.Errorf("orgs can't be empty")
		logger.Error("Generate chainmaker cert failed!", zap.Error(err))
		return filepath, err
	}
	for _, org := range cmCertApplyReq.Orgs {
		if err := CheckOrgInfo(&org); err != nil {
			logger.Error("orginfo is incomplete", zap.Error(err))
			return filepath, err
		}
		//生成公私钥
		var user db.KeyPairUser
		user.CertUsage = db.SIGN
		user.UserType = db.INTERMRDIARY_CA
		user.OrgID = org.OrgID
		privateKey, keyID, err := CreateKeyPair(user, "")
		if err != nil {
			logger.Error("Create ChainMaker org keypair failed!", zap.Error(err))
			return filepath, err
		}
		//生成中间证书的CSR
		O := org.OrgID
		OU := "ca"
		CN := "ca." + O
		csrBytes, err := createCSR(privateKey, org.Country, org.Locality, org.Province, OU,
			O, CN)
		if err != nil {
			logger.Error("Create ChainMaker org CSR failed!", zap.Error(err))
			return filepath, err
		}
		//读取配置文件
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		issuerPrivKeyFilePath, certFilePath := utils.GetRootPrivateKey()
		privKeyRaw, err := ioutil.ReadFile(issuerPrivKeyFilePath)
		if err != nil {
			logger.Error("Read private key file failed!", zap.Error(err))
			return filepath, err
		}
		//私钥解密
		issuerPrivKey, err := decryptPrivKey(privKeyRaw, utils.GetRootCaPrivateKeyPwd(), hashType)
		if err != nil {
			logger.Error("Decrypt private key  failed!", zap.Error(err))
			return filepath, err
		}
		//读取根证书
		certBytes, err := ioutil.ReadFile(certFilePath)
		if err != nil {
			logger.Error("Read cert file failed!", zap.Error(err))
			return filepath, err
		}

		//签发中间CA证书
		certModel, err := IssueCertificate(hashType, true, issuerPrivKey, csrBytes, certBytes, defaultExpireYear, nil)
		if err != nil {
			logger.Error("Issue Cert failed!", zap.Error(err))
			return filepath, err
		}
		certModel.CertStatus = db.EFFECTIVE
		certModel.PrivateKeyID = keyID
		//证书入库
		err = models.InsertCert(certModel)
		if err != nil {
			logger.Error("Insert cert to db failed!", zap.Error(err))
			return filepath, err
		}
		//签发节点sign证书
		err = IssueNodeCert(cmCertApplyReq.ChainID, &org, privateKey, certModel.Content, db.SIGN)
		if err != nil {
			logger.Error("Issue node sign cert failed!", zap.Error(err))
			return filepath, err
		}
		//签发节点TLS证书
		err = IssueNodeCert(cmCertApplyReq.ChainID, &org, privateKey, certModel.Content, db.TLS)
		if err != nil {
			logger.Error("Issue node tls cert failed!", zap.Error(err))
			return filepath, err
		}
		//签发AdminUser证书
		err = IssueAdminUserCert(cmCertApplyReq.ChainID, &org, privateKey, certModel.Content, db.SIGN)
		if err != nil {
			logger.Error("Issue admin user sign cert failed!", zap.Error(err))
			return filepath, err
		}
		err = IssueAdminUserCert(cmCertApplyReq.ChainID, &org, privateKey, certModel.Content, db.TLS)
		if err != nil {
			logger.Error("Issue admin user tls cert failed!", zap.Error(err))
			return filepath, err
		}
		err = IssueUserCert(cmCertApplyReq.ChainID, &org, privateKey, certModel.Content, db.SIGN)
		if err != nil {
			logger.Error("Issue  user sign cert failed!", zap.Error(err))
			return filepath, err
		}
		err = IssueUserCert(cmCertApplyReq.ChainID, &org, privateKey, certModel.Content, db.TLS)
		if err != nil {
			logger.Error("Issue  user tls cert failed!", zap.Error(err))
			return filepath, err
		}
	}
	filepath, err := WriteChainMakerCertFile(cmCertApplyReq)
	if err != nil {
		logger.Error("Write chainmaker cert file failed!", zap.Error(err))
		return filepath, err
	}
	return filepath, nil
}

//IssueNodeCert 签发节点证书
func IssueNodeCert(chainID string, org *models.Org, issurePrivateKey crypto.PrivateKey, certBytes []byte, certUsage db.CertUsage) error {
	for _, node := range org.Nodes {
		var user db.KeyPairUser
		user.CertUsage = certUsage
		user.ChainID = chainID
		user.OrgID = org.OrgID
		user.UserID = node.NodeID
		user.UserType = db.NODE
		//生成公私钥
		privateKey, keyID, err := CreateKeyPair(user, "")
		if err != nil {
			return err
		}
		//生成CSR
		O := org.OrgID
		OU := node.NodeID
		CN := node.NodeID + "." + O
		csrBytes, err := createCSR(privateKey, org.Country, org.Locality, org.Province, OU,
			O, CN)
		if err != nil {
			return err
		}
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		certModel, err := IssueCertificate(hashType, false, issurePrivateKey, csrBytes, certBytes, utils.GetIssureExpirationTime(), node.Sans)
		if err != nil {
			return err
		}
		certModel.CertStatus = db.EFFECTIVE
		certModel.PrivateKeyID = keyID
		err = models.InsertCert(certModel)
		if err != nil {
			return err
		}
	}
	return nil
}

//IssueAdminUserCert .
func IssueAdminUserCert(chainID string, org *models.Org, caPrivKey crypto.PrivateKey, caCertBytes []byte, usage db.CertUsage) error {
	var user db.KeyPairUser
	user.CertUsage = usage
	user.ChainID = chainID
	user.OrgID = org.OrgID
	user.UserID = org.AdminUserID
	user.UserType = db.USER_ADMIN
	//生成公私钥
	privateKey, keyID, err := CreateKeyPair(user, "")
	if err != nil {
		return err
	}
	O := org.OrgID
	OU := org.AdminUserID
	CN := OU + "." + O
	csrBytes, err := createCSR(privateKey, org.Country, org.Locality, org.Province, OU,
		O, CN)
	if err != nil {
		return err
	}
	hashType := crypto.HashAlgoMap[utils.GetHashType()]
	adminCert, err := IssueCertificate(hashType, false, caPrivKey, csrBytes, caCertBytes, utils.GetIssureExpirationTime(), nil)
	adminCert.CertStatus = db.EFFECTIVE
	adminCert.PrivateKeyID = keyID
	//证书入库
	err = models.InsertCert(adminCert)
	if err != nil {
		logger.Error("Insert cert to db failed!", zap.Error(err))
		return err
	}
	return nil
}

//IssueUserCert .
func IssueUserCert(chainID string, org *models.Org, caPrivKey crypto.PrivateKey, caCertBytes []byte, usage db.CertUsage) error {
	for _, userid := range org.Users {
		var user db.KeyPairUser
		user.CertUsage = usage
		user.ChainID = chainID
		user.OrgID = org.OrgID
		user.UserID = userid
		user.UserType = db.USER_USER
		//生成公私钥
		privateKey, keyID, err := CreateKeyPair(user, "")
		if err != nil {
			return err
		}
		O := org.OrgID
		OU := userid
		CN := OU + "." + O
		csrBytes, err := createCSR(privateKey, org.Country, org.Locality, org.Province, OU,
			O, CN)
		if err != nil {
			return err
		}
		hashType := crypto.HashAlgoMap[utils.GetHashType()]
		userCert, err := IssueCertificate(hashType, false, caPrivKey, csrBytes, caCertBytes, utils.GetIssureExpirationTime(), nil)
		userCert.CertStatus = db.EFFECTIVE
		userCert.PrivateKeyID = keyID
		//证书入库
		err = models.InsertCert(userCert)
		if err != nil {
			logger.Error("Insert cert to db failed!", zap.Error(err))
			return err
		}
	}
	return nil
}

//WriteChainMakerCertFile 写证书文件
func WriteChainMakerCertFile(req *models.ChainMakerCertApplyReq) (certBasePath string, err error) {
	if req.Filetarget == "" {
		certBasePath = utils.GetChainMakerCertPath()
	} else {
		certBasePath = req.Filetarget
	}
	for _, org := range req.Orgs {
		orgPath := filepath.Join(certBasePath, org.OrgID)
		err = WriteCaCertFile(orgPath, &org, req.ChainID)
		if err != nil {
			return
		}
		err = WriteNodeCertFile(orgPath, &org, req.ChainID)
		if err != nil {
			return
		}
		err = WriteAdminUserCertFile(orgPath, &org, req.ChainID, org.AdminUserID)
		if err != nil {
			return
		}
		for _, userID := range org.Users {
			fmt.Printf("user_id:%s", userID)
			err = WriteUserCertFile(orgPath, &org, req.ChainID, userID)
			if err != nil {
				return
			}
		}
	}
	return
}

//GetChainMakerCertTar 获取证书压缩包
func GetChainMakerCertTar(filetarget, filesource string) ([]byte, error) {
	if filesource == "" {
		filesource = utils.GetChainMakerCertPath()
	}
	if filetarget == "" {
		filetarget = utils.GetChainMakerCertPath() + ".tar.gz"
		defer func() {
			os.RemoveAll(filetarget)
		}()
	}
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
		nodePath := filepath.Join(orgPath, "node", node.NodeID)
		err := CreateDir(nodePath)
		if err != nil {
			return fmt.Errorf("Create node dir failed: %s", err.Error())
		}
		nodeSignKey, err := models.GetKeyPairByConditions(node.NodeID, org.OrgID, chainID, db.NODE, db.SIGN)
		if err != nil {
			return fmt.Errorf("Get node key by conditions failed: %s", err.Error())
		}
		nodeSignCert, err := models.GetCertByPrivateKeyID(nodeSignKey.ID)
		if err != nil {
			return fmt.Errorf("Get node cert failed: %s", err.Error())
		}
		nodeTLSKey, err := models.GetKeyPairByConditions(node.NodeID, org.OrgID, chainID, db.NODE, db.TLS)
		if err != nil {
			return fmt.Errorf("Get node tls key by conditions failed: %s", err.Error())
		}
		nodeTLSCert, err := models.GetCertByPrivateKeyID(nodeTLSKey.ID)
		if err != nil {
			return fmt.Errorf("Get node tls cert failed: %s", err.Error())
		}
		nodeSignCertPath := filepath.Join(nodePath, node.NodeID+".sign.crt")
		err = ioutil.WriteFile(nodeSignCertPath, nodeSignCert.Content, os.ModePerm)
		if err != nil {
			return fmt.Errorf("Write node sign cert failed: %s", err.Error())
		}
		nodeSignKeyPath := filepath.Join(nodePath, node.NodeID+".sign.key")
		err = ioutil.WriteFile(nodeSignKeyPath, nodeSignKey.PrivateKey, os.ModePerm)
		if err != nil {
			return fmt.Errorf("Write node sign key failed: %s", err.Error())
		}
		nodeTLSCertPath := filepath.Join(nodePath, node.NodeID+".tls.crt")
		err = ioutil.WriteFile(nodeTLSCertPath, nodeTLSCert.Content, os.ModePerm)
		if err != nil {
			return fmt.Errorf("Write node tls cert failed: %s", err.Error())
		}
		nodeTLSKeyPath := filepath.Join(nodePath, node.NodeID+".tls.key")
		err = ioutil.WriteFile(nodeTLSKeyPath, nodeTLSKey.PrivateKey, os.ModePerm)
		if err != nil {
			return fmt.Errorf("Write node tls key failed: %s", err.Error())
		}
	}
	return nil
}

//WriteCaCertFile .
func WriteCaCertFile(orgPath string, org *models.Org, chainID string) error {
	caKey, err := models.GetKeyPairByConditions("", org.OrgID, "", db.INTERMRDIARY_CA, -1)
	if err != nil {
		return fmt.Errorf("Get ca key by conditions failed: %s", err.Error())
	}
	caCert, err := models.GetCertByPrivateKeyID(caKey.ID)
	caPath := filepath.Join(orgPath, "ca")
	caCertPath := filepath.Join(caPath, "ca.crt")
	caKeyPath := filepath.Join(caPath, "ca.key")
	if err := CreateDir(caPath); err != nil {
		return fmt.Errorf("Create ca dir failed: %s", err.Error())
	}
	err = ioutil.WriteFile(caCertPath, caCert.Content, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Write ca Cert file  failed: %s", err.Error())
	}
	err = ioutil.WriteFile(caKeyPath, caKey.PrivateKey, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Write ca key file by failed: %s", err.Error())
	}
	return nil
}

//WriteAdminUserCertFile .
func WriteAdminUserCertFile(orgPath string, org *models.Org, chainID, userID string) error {
	userCertPath := filepath.Join(orgPath, "user", "admin")
	err := CreateDir(userCertPath)
	if err != nil {
		return fmt.Errorf("Create admin user dir failed: %s", err.Error())
	}
	userSignKey, err := models.GetKeyPairByConditions(userID, org.OrgID, chainID, db.USER_ADMIN, db.SIGN)
	if err != nil {
		return fmt.Errorf("Get admin sign key  failed: %s", err.Error())
	}
	userSignCert, err := models.GetCertByPrivateKeyID(userSignKey.ID)
	if err != nil {
		return fmt.Errorf("Get admin sign cert  failed: %s", err.Error())
	}
	userTLSKey, err := models.GetKeyPairByConditions(userID, org.OrgID, chainID, db.USER_ADMIN, db.TLS)
	if err != nil {
		return fmt.Errorf("Get admin tls key  failed: %s", err.Error())
	}
	userTLSCert, err := models.GetCertByPrivateKeyID(userTLSKey.ID)
	if err != nil {
		return fmt.Errorf("Get admin tls cert  failed: %s", err.Error())
	}
	userSignCertPath := filepath.Join(userCertPath, userID+".sign.crt")
	err = ioutil.WriteFile(userSignCertPath, userSignCert.Content, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Write admin user sign cert file failed: %s", err.Error())
	}
	userSignKeyPath := filepath.Join(userCertPath, userID+".sign.key")
	err = ioutil.WriteFile(userSignKeyPath, userSignKey.PrivateKey, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Write admin user sign key failed: %s", err.Error())
	}
	userTLSCertPath := filepath.Join(userCertPath, userID+".tls.crt")
	err = ioutil.WriteFile(userTLSCertPath, userTLSCert.Content, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Write admin user tls cert  file failed: %s", err.Error())
	}
	userTLSKeyPath := filepath.Join(userCertPath, userID+".tls.key")
	err = ioutil.WriteFile(userTLSKeyPath, userTLSKey.PrivateKey, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Write admin user tls  key failed: %s", err.Error())
	}
	return nil
}

//WriteUserCertFile .
func WriteUserCertFile(orgPath string, org *models.Org, chainID, userID string) error {
	userCertPath := filepath.Join(orgPath, "user", "common", userID)
	err := CreateDir(userCertPath)
	if err != nil {
		return err
	}
	userSignKey, err := models.GetKeyPairByConditions(userID, org.OrgID, chainID, db.USER_USER, db.SIGN)
	if err != nil {
		return fmt.Errorf("Get user sign key failed: %s", err.Error())
	}
	userSignCert, err := models.GetCertByPrivateKeyID(userSignKey.ID)
	if err != nil {
		return fmt.Errorf("Get user sign cert failed: %s", err.Error())
	}
	userTLSKey, err := models.GetKeyPairByConditions(userID, org.OrgID, chainID, db.USER_USER, db.TLS)
	if err != nil {
		return fmt.Errorf("Get user tls key failed: %s", err.Error())
	}
	userTLSCert, err := models.GetCertByPrivateKeyID(userTLSKey.ID)
	if err != nil {
		return fmt.Errorf("Get user tls cert failed: %s", err.Error())
	}
	userSignCertPath := filepath.Join(userCertPath, userID+".sign.crt")
	err = ioutil.WriteFile(userSignCertPath, userSignCert.Content, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Write user sign key failed: %s", err.Error())
	}
	userSignKeyPath := filepath.Join(userCertPath, userID+".sign.key")
	err = ioutil.WriteFile(userSignKeyPath, userSignKey.PrivateKey, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Write user sign cert failed: %s", err.Error())
	}
	userTLSCertPath := filepath.Join(userCertPath, userID+".tls.crt")
	err = ioutil.WriteFile(userTLSCertPath, userTLSCert.Content, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Write user tls key failed: %s", err.Error())
	}
	userTLSKeyPath := filepath.Join(userCertPath, userID+".tls.key")
	err = ioutil.WriteFile(userTLSKeyPath, userTLSKey.PrivateKey, os.ModePerm)
	if err != nil {
		return fmt.Errorf("Write user tls cert failed: %s", err.Error())
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
