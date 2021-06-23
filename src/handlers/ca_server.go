/*
Copyright (C) BABEC. All rights reserved.

SPDX-License-Identifier: Apache-2.0
*/

package handlers

import (
	"encoding/pem"
	"fmt"

	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/services"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
)

//Certificates are generated by the CSR
func GenCertByCsr() gin.HandlerFunc {
	return func(c *gin.Context) {
		var req GenCertByCsrReq
		if err := c.ShouldBindBodyWith(&req, binding.JSON); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if err := services.CheckParametersEmpty(req.OrgId,
			req.UserType, req.CertUsage, req.Csr); err != nil {
			InputMissingJSONResp(err.Error(), c)
			return
		}
		curUserType, curCertUsage, err := services.CheckParameters(req.OrgId, req.UserId, req.UserType, req.CertUsage)
		if err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		csrBytes := []byte(req.Csr)
		csr, err := services.ParseCsr(csrBytes)
		if err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if csr.Subject.Organization[0] != req.OrgId || csr.Subject.OrganizationalUnit[0] != req.UserType ||
			curUserType != db.INTERMRDIARY_CA && csr.Subject.CommonName != req.UserId {
			err := fmt.Errorf("the requested information does not match the CSR")
			InputErrorJSONResp(err.Error(), c)
			return
		}
		certContent, err := services.GenCertByCsr(&services.GenCertByCsrReq{
			OrgId:     req.OrgId,
			UserId:    req.UserId,
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

//Generate certificate
func GenCert() gin.HandlerFunc {
	return func(c *gin.Context) {
		var genCertReq GenCertReq
		if err := c.ShouldBindBodyWith(&genCertReq, binding.JSON); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if err := services.CheckParametersEmpty(genCertReq.OrgId, genCertReq.UserType,
			genCertReq.CertUsage, genCertReq.Country, genCertReq.Locality, genCertReq.Province); err != nil {
			InputMissingJSONResp(err.Error(), c)
			return
		}
		curUserType, curCertUsage, err := services.CheckParameters(genCertReq.OrgId, genCertReq.UserId, genCertReq.UserType, genCertReq.CertUsage)
		if err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}

		certContentAndPrivateKey, err := services.GenCert(&services.GenCertReq{
			OrgId:         genCertReq.OrgId,
			UserId:        genCertReq.UserId,
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

//Query certificates
func QueryCerts() gin.HandlerFunc {
	return func(c *gin.Context) {
		var queryCertReq QueryCertReq
		if err := c.ShouldBindBodyWith(&queryCertReq, binding.JSON); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		certInfos, err := services.QueryCerts(&services.QueryCertsReq{
			OrgId:     queryCertReq.OrgId,
			UserId:    queryCertReq.UserId,
			UserType:  queryCertReq.UserType,
			CertUsage: queryCertReq.CertUsage,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		SuccessfulJSONResp("", certInfos, c)
	}
}

//renew certificate
func RenewCert() gin.HandlerFunc {
	return func(c *gin.Context) {
		if services.IsAccessControlFromConfig() {
			role, err := accessControl(c)
			if err != nil {
				ServerErrorJSONResp(err.Error(), c)
				return
			}
			if role != db.ADMIN {
				err := fmt.Errorf("permission denied")
				ServerErrorJSONResp(err.Error(), c)
				return
			}
		}
		var renewCertReq RenewCertReq
		if err := c.ShouldBindBodyWith(&renewCertReq, binding.JSON); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if renewCertReq.CertSn == 0 {
			err := fmt.Errorf("cert sn cannot be empty")
			InputErrorJSONResp(err.Error(), c)
			return
		}
		certContent, err := services.RenewCert(&services.RenewCertReq{
			CertSn: renewCertReq.CertSn,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		SuccessfulJSONResp("", certContent, c)
	}
}

//Revoke certificate
func RevokeCert() gin.HandlerFunc {
	return func(c *gin.Context) {
		if services.IsAccessControlFromConfig() {
			role, err := accessControl(c)
			if err != nil {
				ServerErrorJSONResp(err.Error(), c)
				return
			}
			if role != db.ADMIN {
				err := fmt.Errorf("permission denied")
				ServerErrorJSONResp(err.Error(), c)
				return
			}
		}
		var revokeCertReq RevokeCertReq
		if err := c.ShouldBindBodyWith(&revokeCertReq, binding.JSON); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if revokeCertReq.IssuerCertSn == 0 || revokeCertReq.RevokedCertSn == 0 {
			err := fmt.Errorf("input issue sn or revoked sn is illegal")
			InputErrorJSONResp(err.Error(), c)
			return
		}
		crlBytes, err := services.RevokeCert(&services.RevokeCertReq{
			RevokedCertSn: revokeCertReq.RevokedCertSn,
			IssuerCertSn:  revokeCertReq.IssuerCertSn,
			Reason:        revokeCertReq.Reason,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		crlBytes = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
		SuccessfulJSONResp("", string(crlBytes), c)
	}
}

//Generate crl
func GenCrl() gin.HandlerFunc {
	return func(c *gin.Context) {
		var genCrlReq GenCrlReq
		if err := c.ShouldBindBodyWith(&genCrlReq, binding.JSON); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if genCrlReq.IssuerCertSn == 0 {
			err := fmt.Errorf("issuer cert sn cannot be empty")
			InputErrorJSONResp(err.Error(), c)
			return
		}
		crlBytes, err := services.GenCrl(&services.GenCrlReq{
			IssuerCertSn: genCrlReq.IssuerCertSn,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		crlBytes = pem.EncodeToMemory(&pem.Block{Type: "X509 CRL", Bytes: crlBytes})
		SuccessfulJSONResp("", string(crlBytes), c)
	}
}

//generate csr
func GenCsr() gin.HandlerFunc {
	return func(c *gin.Context) {
		var genCsrReq GenCsrReq
		if err := c.ShouldBindBodyWith(&genCsrReq, binding.JSON); err != nil {
			InputErrorJSONResp(err.Error(), c)
			return
		}
		if err := services.CheckParametersEmpty(genCsrReq.OrgId, genCsrReq.UserType,
			genCsrReq.Country, genCsrReq.Locality, genCsrReq.Province); err != nil {
			InputMissingJSONResp(err.Error(), c)
			return
		}
		curUserType, err := services.CheckParametersUserType(genCsrReq.UserType)
		if err != nil {
			InputMissingJSONResp(err.Error(), c)
			return
		}
		csrByte, err := services.GenCsr(&services.GenCsrReq{
			OrgId:         genCsrReq.OrgId,
			UserId:        genCsrReq.UserId,
			UserType:      curUserType,
			PrivateKeyPwd: genCsrReq.PrivateKeyPwd,
			Country:       genCsrReq.Country,
			Locality:      genCsrReq.Locality,
			Province:      genCsrReq.Province,
		})
		if err != nil {
			ServerErrorJSONResp(err.Error(), c)
			return
		}
		SuccessfulJSONResp("", string(csrByte), c)
	}
}
