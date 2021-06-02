package handlers

import (
	"encoding/base64"
	"encoding/pem"
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/services"
	"github.com/gin-gonic/gin"
)

//先Bind
//判断空
//判断内容

//这个特殊之后单独的改定
func GenerateCertByCsr() gin.HandlerFunc {
	return func(c *gin.Context) {
		//从新更改从前端拿数据的模式，这里是先通过表单拿到id类数据，再通过文件上传形式拿到csr流文件
		orgID := c.PostForm("orgId")
		userID := c.PostForm("userId")
		userType := c.PostForm("userType")
		certUsage := c.PostForm("certUsage")
		if err := services.CheckParametersEmpty(orgID, userID, userType, certUsage); err != nil {
			InputMissingJSONResp(err.Error(), c)
			return
		}
		curUserType, curCertUsage, err := services.CheckParameters(orgID, userID, userType, certUsage)
		if err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		//单独读取上传文件，读出csr流文件
		upLoadFile, err := c.FormFile("csrFile")
		if err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		file, err := upLoadFile.Open()
		if err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		defer file.Close()
		csrBytes, err := services.ReadWithFile(file)
		if err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		_, err = services.ParseCsr(csrBytes)
		if err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		certContent, err := services.GenerateCertByCsr(&services.GenerateCertByCsrReq{
			OrgID:     orgID,
			UserID:    userID,
			UserType:  curUserType,
			CertUsage: curCertUsage,
			CsrBytes:  csrBytes,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		SuccessfulJSONResp("", certContent, c)
	}
}

func GenCert() gin.HandlerFunc {
	return func(c *gin.Context) {
		var genCertReq models.GenCertReq
		if err := c.ShouldBind(&genCertReq); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if err := services.CheckParametersEmpty(genCertReq.OrgID, genCertReq.UserID,
			genCertReq.UserType, genCertReq.CertUsage, genCertReq.PrivateKeyPwd,
			genCertReq.Country, genCertReq.Locality, genCertReq.Province); err != nil {
			InputMissingJSONResp(err.Error(), c)
			return
		}
		curUserType, curCertUsage, err := services.CheckParameters(genCertReq.OrgID, genCertReq.UserID, genCertReq.UserType, genCertReq.CertUsage)
		if err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}

		certContentAndPrivateKey, err := services.GenCert(&services.GenCertReq{
			OrgID:         genCertReq.OrgID,
			UserID:        genCertReq.UserID,
			UserType:      curUserType,
			CertUsage:     curCertUsage,
			PrivateKeyPwd: genCertReq.PrivateKeyPwd,
			Country:       genCertReq.Country,
			Locality:      genCertReq.Locality,
			Province:      genCertReq.Province,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		SuccessfulJSONResp("", certContentAndPrivateKey, c)
	}
}

func QueryCert() gin.HandlerFunc {
	return func(c *gin.Context) {
		var queryCertReq models.QueryCertReq
		if err := c.ShouldBind(&queryCertReq); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if err := services.CheckParametersEmpty(queryCertReq.OrgID, queryCertReq.UserID,
			queryCertReq.UserType, queryCertReq.CertUsage); err != nil {
			InputMissingJSONResp(err.Error(), c)
			return
		}
		curUserType, curCertUsage, err := services.CheckParameters(queryCertReq.OrgID, queryCertReq.UserID, queryCertReq.UserType, queryCertReq.CertUsage)
		if err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		queryCertResp, err := services.QueryCert(&services.QueryCertReq{
			OrgID:     queryCertReq.OrgID,
			UserID:    queryCertReq.UserID,
			UserType:  curUserType,
			CertUsage: curCertUsage,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		SuccessfulJSONResp("", queryCertResp, c)
	}
}

func QueryCertByStatus() gin.HandlerFunc {
	return func(c *gin.Context) {
		var queryCertByStatusReq models.QueryCertByStatusReq
		if err := c.ShouldBind(&queryCertByStatusReq); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if err := services.CheckParametersEmpty(queryCertByStatusReq.OrgID, queryCertByStatusReq.UserID,
			queryCertByStatusReq.UserType, queryCertByStatusReq.CertUsage); err != nil {
			InputMissingJSONResp(err.Error(), c)
			return
		}
		curUserType, curCertUsage, err := services.CheckParameters(queryCertByStatusReq.OrgID, queryCertByStatusReq.UserID, queryCertByStatusReq.UserType, queryCertByStatusReq.CertUsage)
		if err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		curCertStatus, ok := db.Name2CertStatusMap[queryCertByStatusReq.CertStatus]
		if !ok {
			err := fmt.Errorf("the Cert Status does not meet the requirements")
			InputErrorJSONResp(err.Error(), c)
			return
		}
		queryCertRespList, err := services.QueryCertByStatus(&services.QueryCertByStatusReq{
			OrgID:      queryCertByStatusReq.OrgID,
			UserID:     queryCertByStatusReq.UserID,
			UserType:   curUserType,
			CertUsage:  curCertUsage,
			CertStatus: curCertStatus,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		SuccessfulJSONResp("", queryCertRespList, c)
	}
}

func UpdateCert() gin.HandlerFunc {
	return func(c *gin.Context) {
		var updatecertReq models.UpdateCertReq
		if err := c.ShouldBind(&updatecertReq); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if updatecertReq.CertSn == 0 {
			err := fmt.Errorf("input SN is illegal")
			InputErrorJSONResp(err.Error(), c)
			return
		}
		certContent, err := services.UpdateCert(&services.UpdateCertReq{
			CertSn: updatecertReq.CertSn,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		SuccessfulJSONResp("", certContent, c)
	}
}

func RevokedCert() gin.HandlerFunc {
	return func(c *gin.Context) {
		var revokedCertReq models.RevokedCertReq
		if err := c.ShouldBind(&revokedCertReq); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if revokedCertReq.IssueCertSn == 0 || revokedCertReq.RevokedCertSn == 0 || revokedCertReq.RevokedEndTime == 0 || revokedCertReq.RevokedEndTime == 0 {
			err := fmt.Errorf("input SN or Time is illegal")
			InputErrorJSONResp(err.Error(), c)
			return
		}
		crlList, err := services.RevokedCert(&services.RevokedCertReq{
			RevokedCertSn:    revokedCertReq.RevokedCertSn,
			IssueCertSn:      revokedCertReq.IssueCertSn,
			Reason:           revokedCertReq.Reason,
			RevokedStartTime: revokedCertReq.RevokedStartTime,
			RevokedEndTime:   revokedCertReq.RevokedEndTime,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}

		crlList = pem.EncodeToMemory(&pem.Block{Type: "CRL", Bytes: crlList})
		reCrlList := base64.StdEncoding.EncodeToString(crlList)
		SuccessfulJSONResp("", reCrlList, c)
	}
}

func CrlList() gin.HandlerFunc {
	return func(c *gin.Context) {
		var crlListReq models.CrlListReq
		if err := c.ShouldBind(&crlListReq); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if crlListReq.IssueCertSn == 0 {
			err := fmt.Errorf("input SN is illegal")
			InputErrorJSONResp(err.Error(), c)
			return
		}
		crlList, err := services.CrlList(&services.CrlListReq{
			IssueCertSn: crlListReq.IssueCertSn,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		crlList = pem.EncodeToMemory(&pem.Block{Type: "CRL", Bytes: crlList})
		reCrlList := base64.StdEncoding.EncodeToString(crlList)
		SuccessfulJSONResp("", reCrlList, c)
	}
}

func CreateCsr() gin.HandlerFunc {
	return func(c *gin.Context) {
		var createCsrReq models.CreateCsrReq
		if err := c.ShouldBind(&createCsrReq); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if err := services.CheckParametersEmpty(createCsrReq.OrgID, createCsrReq.UserID,
			createCsrReq.UserType, createCsrReq.PrivateKeyPwd,
			createCsrReq.Country, createCsrReq.Locality, createCsrReq.Province); err != nil {
			InputMissingJSONResp(err.Error(), c)
			return
		}
		curUserType, err := services.CheckParametersUserType(createCsrReq.UserType)
		if err != nil {
			InputMissingJSONResp(err.Error(), c)
			return
		}
		csrByte, err := services.CreateCsr(&services.CreateCsrReq{
			OrgID:         createCsrReq.OrgID,
			UserID:        createCsrReq.UserID,
			UserType:      curUserType,
			PrivateKeyPwd: createCsrReq.PrivateKeyPwd,
			Country:       createCsrReq.Country,
			Locality:      createCsrReq.Locality,
			Province:      createCsrReq.Province,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		reCsr := base64.StdEncoding.EncodeToString(csrByte)
		SuccessfulJSONResp("", reCsr, c)
	}
}
