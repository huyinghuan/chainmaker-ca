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

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
	"chainmaker.org/chainmaker-go/common/crypto"
)

//GenerateChainMakerCert 生成chainmaker全套证书
func GenerateChainMakerCert(cmCertApplyReq *models.ChainMakerCertApplyReq) (string, error) {
	//首先每个组织是root签发的一个中间CA
	//循环签发出中间CA
	var filepath string
	for _, org := range cmCertApplyReq.Orgs {
		err := CheckOrgInfo(&org)
		if err != nil {
			return filepath, err
		}
		err = IssueOrgCACert(&org, "", defaultExpireYear)
		if err != nil {
			return filepath, err
		}
		//签发节点sign证书
		err = IssueNodeCert(&org, db.SIGN)
		if err != nil {
			return filepath, err
		}
		//签发节点TLS证书
		err = IssueNodeCert(&org, db.TLS)
		if err != nil {
			return filepath, err
		}
		err = IssueUserCert(&org, db.SIGN)
		if err != nil {
			return filepath, err
		}
		err = IssueUserCert(&org, db.TLS)
		if err != nil {
			return filepath, err
		}
	}
	filepath, err := WriteChainMakerCertFile(cmCertApplyReq)
	if err != nil {
		return filepath, err
	}
	return filepath, nil
}

//IssueNodeCert 签发节点证书
func IssueNodeCert(org *models.Org, certUsage db.CertUsage) error {
	certAndPrivKeys, err := GetCertByConditions("", org.OrgID, -1, db.INTERMRDIARY_CA)
	if err != nil {
		return err
	}
	if certAndPrivKeys == nil {
		return fmt.Errorf("[issue node cert] org ca cert is not exist")
	}
	issuerPrivKey := certAndPrivKeys[0].PrivKey
	issueCert := certAndPrivKeys[0].Cert
	for _, node := range org.Nodes {
		if node.NodeID == "" || (node.NodeType != db.NODE_COMMON && node.NodeType != db.NODE_CONSENSUS) {
			return fmt.Errorf("[issue node cert] there is a problem with node information")
		}
		var user db.KeyPairUser
		user.CertUsage = certUsage
		user.OrgID = org.OrgID
		user.UserID = node.NodeID
		user.UserType = node.NodeType
		privateKey, keyID, err := CreateKeyPair(org.PrivateKeyType, org.HashType, &user, "", false)
		if err != nil {
			return err
		}

		//生成CSR
		O := org.OrgID
		OU := db.UserType2NameMap[user.UserType]
		CN := node.NodeID + "-" + O
		csrBytes, err := createCSR(privateKey, org.Country, org.Locality, org.Province, OU,
			O, CN)
		if err != nil {
			return err
		}
		hashType := crypto.HashAlgoMap[utils.GetInputOrDefault(org.HashType, utils.GetHashType())]
		_, err = IssueCertificate(hashType, false, keyID, issuerPrivKey, csrBytes, issueCert.Content, utils.GetIssureExpirationTime(), node.Sans)
		if err != nil {
			return err
		}
	}
	return nil
}

//IssueUserCert .
func IssueUserCert(org *models.Org, usage db.CertUsage) error {
	certAndPrivKeys, err := GetCertByConditions("", org.OrgID, -1, db.INTERMRDIARY_CA)
	if err != nil {
		return err
	}
	if certAndPrivKeys == nil {
		return fmt.Errorf("[issuer user cert] org ca cert is not exist")
	}
	issuerPrivKey := certAndPrivKeys[0].PrivKey
	issueCert := certAndPrivKeys[0].Cert
	for _, v := range org.Users {
		if v.UserName == "" || (v.UserType != db.USER_ADMIN && v.UserType != db.USER_USER) {
			return fmt.Errorf("[issuer user cert] there is a problem with node information")
		}
		var user db.KeyPairUser
		user.CertUsage = usage
		user.OrgID = org.OrgID
		user.UserID = v.UserName
		user.UserType = v.UserType
		var isKms bool
		if utils.GetGenerateKeyPairType() && user.CertUsage == db.SIGN && user.UserType == db.USER_USER {
			isKms = true
		}
		privateKey, keyID, err := CreateKeyPair(org.PrivateKeyType, org.HashType, &user, "", isKms)
		if err != nil {
			return err
		}

		O := org.OrgID
		OU := db.UserType2NameMap[user.UserType]
		CN := user.UserID + "." + O
		csrBytes, err := createCSR(privateKey, org.Country, org.Locality, org.Province, OU,
			O, CN)
		if err != nil {
			return err
		}
		hashType := crypto.HashAlgoMap[utils.GetInputOrDefault(org.HashType, utils.GetHashType())]
		_, err = IssueCertificate(hashType, false, keyID, issuerPrivKey, csrBytes, issueCert.Content, utils.GetIssureExpirationTime(), nil)
		if err != nil {
			return err
		}
	}
	return nil
}

//IssueUserCertWithStatus .
func IssueUserCertWithStatus(org *models.Org, usage db.CertUsage) error {
	certAndPrivKeys, err := GetCertByConditions("", org.OrgID, -1, db.INTERMRDIARY_CA)
	if err != nil {
		return err
	}
	if certAndPrivKeys == nil {
		return fmt.Errorf("[issuer user cert] org ca cert is not exist")
	}
	issuerPrivKey := certAndPrivKeys[0].PrivKey
	issueCert := certAndPrivKeys[0].Cert
	for _, v := range org.Users {
		if v.UserName == "" || (v.UserType != db.USER_ADMIN && v.UserType != db.USER_USER) {
			return fmt.Errorf("[issuer user cert] there is a problem with node information")
		}
		var user db.KeyPairUser
		user.CertUsage = usage
		user.OrgID = org.OrgID
		user.UserID = v.UserName
		user.UserType = v.UserType
		var isKms bool
		if utils.GetGenerateKeyPairType() && user.CertUsage == db.SIGN && user.UserType == db.USER_USER {
			isKms = true
		}
		privateKey, keyID, err := CreateKeyPair(org.PrivateKeyType, org.HashType, &user, "", isKms)
		if err != nil {
			return err
		}

		O := org.OrgID
		OU := db.UserType2NameMap[user.UserType]
		CN := user.UserID + "." + O
		csrBytes, err := createCSR(privateKey, org.Country, org.Locality, org.Province, OU,
			O, CN)
		if err != nil {
			return err
		}
		hashType := crypto.HashAlgoMap[utils.GetInputOrDefault(org.HashType, utils.GetHashType())]
		_, err = IssueCertificateCheckStatus(hashType, false, keyID, issuerPrivKey, csrBytes, issueCert.Content, utils.GetIssureExpirationTime(), nil)
		if err != nil {
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
	if utils.CheckPathExist(certBasePath) {
		os.RemoveAll(certBasePath)
	}
	for _, org := range req.Orgs {
		orgPath := filepath.Join(certBasePath, org.OrgID)
		err = WriteCaCertFile(orgPath, &org)
		if err != nil {
			return
		}
		err = WriteNodeCertFile(orgPath, &org)
		if err != nil {
			return
		}
		err = WriteUserCertFile(orgPath, &org)
		if err != nil {
			return
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
		return nil, err
	}
	dataBytes, err := ioutil.ReadFile(filetarget)
	if err != nil {
		return nil, fmt.Errorf("[Get cert tar] read file error: %s", err.Error())
	}
	return dataBytes, nil
}

//WriteNodeCertFile .
func WriteNodeCertFile(orgPath string, org *models.Org) error {
	for _, node := range org.Nodes {
		nodePath := filepath.Join(orgPath, "node", node.NodeID)
		err := CreateDir(nodePath)
		if err != nil {
			return err
		}
		userID := node.NodeID
		certAndPrivKeys, err := GetCertByConditions(userID, org.OrgID, -1, node.NodeType)
		if err != nil {
			return err
		}
		if certAndPrivKeys == nil {
			return fmt.Errorf("[Write node cert file] org ca cert is not exist")
		}
		var (
			nodeSignCert []byte
			nodeTLSCert  []byte
			nodeSignKey  []byte
			nodeTLSKey   []byte
			certSN       int64
		)
		for _, v := range certAndPrivKeys {
			if v.KeyPair.CertUsage == db.SIGN {
				nodeSignCert = v.Cert.Content
				nodeSignKey = v.KeyPair.PrivateKey
			}
			if v.KeyPair.CertUsage == db.TLS {
				nodeTLSCert = v.Cert.Content
				nodeTLSKey = v.KeyPair.PrivateKey
				certSN = v.Cert.SerialNumber
			}
		}
		nodeSignCertPath := filepath.Join(nodePath, node.NodeID+".sign.crt")
		err = ioutil.WriteFile(nodeSignCertPath, nodeSignCert, os.ModePerm)
		if err != nil {
			return fmt.Errorf("[Write node cert file] wirte node sign cert error: %s", err.Error())
		}
		nodeSignKeyPath := filepath.Join(nodePath, node.NodeID+".sign.key")
		err = ioutil.WriteFile(nodeSignKeyPath, nodeSignKey, os.ModePerm)
		if err != nil {
			return fmt.Errorf("[Write node cert file] wirte node sign key error: %s", err.Error())
		}
		nodeTLSCertPath := filepath.Join(nodePath, node.NodeID+".tls.crt")
		err = ioutil.WriteFile(nodeTLSCertPath, nodeTLSCert, os.ModePerm)
		if err != nil {
			return fmt.Errorf("[Write node cert file] wirte node tls cert error: %s", err.Error())
		}
		nodeTLSKeyPath := filepath.Join(nodePath, node.NodeID+".tls.key")
		err = ioutil.WriteFile(nodeTLSKeyPath, nodeTLSKey, os.ModePerm)
		if err != nil {
			return fmt.Errorf("[Write node cert file] wirte node tls key error: %s", err.Error())
		}

		nodeId, err := GetAndSaveNodeID(nodeTLSCert, certSN)
		if err != nil {
			return fmt.Errorf("[Write node cert file] get node Id error: %s", err.Error())
		}
		nodeIdPath := filepath.Join(nodePath, node.NodeID+".nodeid")
		err = ioutil.WriteFile(nodeIdPath, []byte(nodeId), os.ModePerm)
		if err != nil {
			return fmt.Errorf("[Write node cert file] wirte node Id error: %s", err.Error())
		}
	}
	return nil
}

//WriteCaCertFile .
func WriteCaCertFile(orgPath string, org *models.Org) error {
	certAndPrivKeys, err := GetCertByConditions("", org.OrgID, -1, db.INTERMRDIARY_CA)
	if err != nil {
		return err
	}
	if certAndPrivKeys == nil {
		return fmt.Errorf("[Write ca cert file] org ca cert is not exist")
	}
	caKey := certAndPrivKeys[0].KeyPair
	caCert := certAndPrivKeys[0].Cert
	caPath := filepath.Join(orgPath, "ca")
	caCertPath := filepath.Join(caPath, "ca.crt")
	caKeyPath := filepath.Join(caPath, "ca.key")
	if err := CreateDir(caPath); err != nil {
		return err
	}
	err = ioutil.WriteFile(caCertPath, caCert.Content, os.ModePerm)
	if err != nil {
		return fmt.Errorf("[Write ca cert file] write ca cert file error: %s", err.Error())
	}
	err = ioutil.WriteFile(caKeyPath, caKey.PrivateKey, os.ModePerm)
	if err != nil {
		return fmt.Errorf("[Write ca cert file] write ca key file error: %s", err.Error())
	}
	return nil
}

//WriteUserCertFile .
func WriteUserCertFile(orgPath string, org *models.Org) error {
	for _, v := range org.Users {
		userCertPath := filepath.Join(orgPath, "user", v.UserName)
		err := CreateDir(userCertPath)
		if err != nil {
			return err
		}
		certAndPrivKeys, err := GetCertByConditions(v.UserName, org.OrgID, -1, v.UserType)
		if err != nil {
			return err
		}
		if certAndPrivKeys == nil {
			return fmt.Errorf("[Wirte user cert file] org ca cert is not exist")
		}

		var (
			userSignCert []byte
			userTLSCert  []byte
			userSignKey  []byte
			userTLSKey   []byte
		)
		for _, v := range certAndPrivKeys {
			if v.KeyPair.CertUsage == db.SIGN {
				userSignCert = v.Cert.Content
				userSignKey = v.KeyPair.PrivateKey
			}
			if v.KeyPair.CertUsage == db.TLS {
				userTLSCert = v.Cert.Content
				userTLSKey = v.KeyPair.PrivateKey
			}
		}
		userSignCertPath := filepath.Join(userCertPath, v.UserName+".sign.crt")
		err = ioutil.WriteFile(userSignCertPath, userSignCert, os.ModePerm)
		if err != nil {
			return fmt.Errorf("[Wirte user cert file] write user sign sign error: %s", err.Error())
		}
		userSignKeyPath := filepath.Join(userCertPath, v.UserName+".sign.key")
		err = ioutil.WriteFile(userSignKeyPath, userSignKey, os.ModePerm)
		if err != nil {
			return fmt.Errorf("[Wirte user cert file] write user sign key error: %s", err.Error())
		}
		userTLSCertPath := filepath.Join(userCertPath, v.UserName+".tls.crt")
		err = ioutil.WriteFile(userTLSCertPath, userTLSCert, os.ModePerm)
		if err != nil {
			return fmt.Errorf("[Wirte user cert file] write user tls sign error: %s", err.Error())
		}
		userTLSKeyPath := filepath.Join(userCertPath, v.UserName+".tls.key")
		err = ioutil.WriteFile(userTLSKeyPath, userTLSKey, os.ModePerm)
		if err != nil {
			return fmt.Errorf("[Wirte user cert file] write user tls key error: %s", err.Error())
		}
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
			return fmt.Errorf("[Tar] os create error: %s", err.Error())
		}
	}
	defer fw.Close()
	gw := gzip.NewWriter(fw)
	defer gw.Close()
	// 创建 tar.Writer，执行打包操作
	tw := tar.NewWriter(gw)
	defer func() {
		// 这里要判断 tw 是否关闭成功，如果关闭失败，则 .tar 文件可能不完整
		if er := tw.Close(); er != nil {
			err = fmt.Errorf("[Tar] writer close error: %s", er.Error())
		}
	}()

	// 获取文件或目录信息
	fi, err := os.Stat(filesource)
	if err != nil {
		return fmt.Errorf("[Tar] os stat error: %s", err.Error())
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
		return fmt.Errorf("[Tar dir] read dir error: %s", er.Error())
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
			return fmt.Errorf("[Tar dir] tar file info header error: %s", err.Error())
		}
		hdr.Name = srcRelative

		if er = tw.WriteHeader(hdr); er != nil {
			return fmt.Errorf("[Tar dir] writer header error: %s", err.Error())
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
		return fmt.Errorf("[Tar file] tar file info header  error: %s", er.Error())
	}
	hdr.Name = srcRelative

	if er = tw.WriteHeader(hdr); er != nil {
		return fmt.Errorf("[Tar dir] write header error: %s", er.Error())
	}

	// 打开要打包的文件，准备读取
	fr, er := os.Open(srcFull)
	if er != nil {
		return fmt.Errorf("[Tar dir] os open error: %s", er.Error())
	}
	defer fr.Close()

	// 将文件数据写入 tw 中
	if _, er = io.Copy(tw, fr); er != nil {
		return fmt.Errorf("[Tar dir] io copy error: %s", er.Error())
	}
	return nil
}
