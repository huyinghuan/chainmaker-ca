package services

import (
	"context"
	"net"

	pb "chainmaker.org/chainmaker-ca-backend/src/cmservice"
	"chainmaker.org/chainmaker-ca-backend/src/models"
	"chainmaker.org/chainmaker-ca-backend/src/models/db"
	"chainmaker.org/chainmaker-ca-backend/src/utils"
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
		logger.Error("[rpc server] Generate chainmaker cert error", zap.Error(err))
		return nil, err
	}
	resp.Filepath = certpath
	return &resp, nil
}

//GetCertTar .
func (c *ChainMakerCertService) GetCertTar(ctx context.Context, req *pb.GetCertTarReq) (*pb.TarCertResp, error) {
	var resp pb.TarCertResp
	certFileBytes, err := GetChainMakerCertTar(req.Filetarget, req.Filesource)
	if err != nil {
		logger.Error("[rpc server] Get chainmaker cert tar error", zap.Error(err))
		return nil, err
	}
	resp.Certfile = certFileBytes
	return &resp, nil
}

//GetCertByConditions .
func (c *ChainMakerCertService) GetCertByConditions(ctx context.Context, req *pb.GetCertReq) (*pb.GetCertResp, error) {
	var (
		usage         db.CertUsage
		userType      db.UserType
		pbGetCertResp pb.GetCertResp
	)
	if req.Usage == -1 {
		usage = -1
	} else {
		usage = db.Name2CertUsageMap[req.Usage.String()]
	}
	if req.Type == -1 {
		userType = -1
	} else {
		userType = db.Name2UserTypeMap[req.Type.String()]
	}
	getCertResps, err := GetCert(req.UserId, req.OrgId, usage, userType)
	if err != nil {
		logger.Error("[rpc server] get cert by conditions error", zap.Error(err))
		return nil, err
	}
	var certKeys []*pb.CertAndPrivKey = make([]*pb.CertAndPrivKey, len(getCertResps))
	for i, v := range getCertResps {
		certKeys[i].CertContent = v.CertContent
		certKeys[i].PrivateKey = v.PrivateKey
		certKeys[i].Usage = v.Usage
	}
	pbGetCertResp.CertKey = certKeys
	return &pbGetCertResp, nil
}
func pbtransform(req *pb.ChainMakerCertApplyReq) *models.ChainMakerCertApplyReq {
	var modelReq models.ChainMakerCertApplyReq
	var modelOrgs []models.Org
	modelReq.Filetarget = req.Filetarget
	for _, org := range req.Orgs {
		var modelOrg models.Org
		var modelNodes []models.Node
		var modelUsers []models.User
		modelOrg.Country = org.Country
		modelOrg.Locality = org.Locality
		modelOrg.Province = org.Province
		modelOrg.OrgID = org.OrgId
		for _, node := range org.Nodes {
			var modelNode models.Node
			modelNode.NodeID = node.NodeId
			modelNode.NodeType = db.Name2UserTypeMap[node.Type.String()]
			modelNode.Sans = node.Sans
			modelNodes = append(modelNodes, modelNode)
		}
		for _, user := range org.Users {
			var modelUser models.User
			modelUser.UserName = user.UserName
			modelUser.UserType = db.Name2UserTypeMap[user.Type.String()]
			modelUsers = append(modelUsers, modelUser)
		}
		modelOrg.Nodes = modelNodes
		modelOrg.Users = modelUsers
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
		logger.Error("[RPC server] init rpc server error", zap.Error(err))
		return
	}
	s := grpc.NewServer()                           // 创建gRPC服务器
	pb.RegisterChainMakerCertApplyServer(s, server) // 在gRPC服务端注册服务
	err = s.Serve(lis)
	if err != nil {
		logger.Error("[RPC server] init rpc server error", zap.Error(err))
		return
	}
}
