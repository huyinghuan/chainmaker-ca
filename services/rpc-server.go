package services

import (
	"context"
	"net"

	pb "chainmaker.org/wx-CRA-backend/cmservice"
	"chainmaker.org/wx-CRA-backend/models"
	"chainmaker.org/wx-CRA-backend/utils"
	"go.uber.org/zap"
	"google.golang.org/grpc"
)

//ChainMakerCertService .
type ChainMakerCertService struct{}

//GenerateCert .实现
func (c *ChainMakerCertService) GenerateCert(ctx context.Context, req *pb.ChainMakerCertApplyReq) (*pb.GenerateResp, error) {
	var resp pb.GenerateResp
	modelReq := pbtransform(req)
	certpath, err := GenerateChainMakerCert(modelReq)
	if err != nil {
		logger.Error("[rpc server] Generate chainmaker cert failed!", zap.Error(err))
		return nil, err
	}
	resp.Filepath = certpath
	return &resp, nil
}
func (c *ChainMakerCertService) GetCertTar(ctx context.Context, req *pb.GetCertTarReq) (*pb.TarCertResp, error) {
	var resp pb.TarCertResp
	certFileBytes, err := GetChainMakerCertTar(req.Filetarget, req.Filesource)
	if err != nil {
		logger.Error("[rpc server] Get chainmaker cert failed!", zap.Error(err))
		return nil, err
	}
	resp.Certfile = certFileBytes
	return &resp, nil
}
func pbtransform(req *pb.ChainMakerCertApplyReq) *models.ChainMakerCertApplyReq {
	var modelReq models.ChainMakerCertApplyReq
	var modelOrgs []models.Org
	modelReq.ChainID = req.ChainId
	modelReq.Filetarget = req.Filetarget
	for _, org := range req.Orgs {
		var modelOrg models.Org
		var modelNodes []models.Node
		modelOrg.UserID = int(org.UserId)
		modelOrg.CommonName = org.CommonName
		modelOrg.Country = org.Country
		modelOrg.Locality = org.Locality
		modelOrg.Organization = org.Organization
		modelOrg.OrganizationalUnit = org.OrganizationUnit
		modelOrg.Province = org.Province
		for _, node := range org.Nodes {
			var modelNode models.Node
			modelNode.NodeName = node.NodeName
			modelNode.Sans = node.Sans
			modelNodes = append(modelNodes, modelNode)
		}
		modelOrg.Nodes = modelNodes
		modelOrgs = append(modelOrgs, modelOrg)
	}
	modelReq.Orgs = modelOrgs
	return &modelReq
}

//InitRPCServer init
func InitRPCServer() {
	var server = &ChainMakerCertService{}
	port := utils.GetChainMakerCertRPCServerPort()
	lis, err := net.Listen("tcp", port)
	if err != nil {
		logger.Error("[RPC server] Init rpc server failed!", zap.Error(err))
		return
	}
	s := grpc.NewServer()                           // 创建gRPC服务器
	pb.RegisterChainMakerCertApplyServer(s, server) // 在gRPC服务端注册服务
	err = s.Serve(lis)
	if err != nil {
		logger.Error("[RPC server] Init rpc server failed!", zap.Error(err))
		return
	}
}
