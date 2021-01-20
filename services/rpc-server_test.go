package services

import (
	"context"
	"fmt"
	"log"
	"testing"

	pb "chainmaker.org/wx-CRA-backend/cmservice"
	"google.golang.org/grpc"
)

func TestGetChainMakerTar(t *testing.T) {
	conn, err := grpc.Dial(":2333", grpc.WithInsecure())

	if err != nil {

		log.Fatalf("dial error: %v\n", err)

	}

	defer conn.Close()

	//实例化 UserInfoService 微服务的客户端

	client := pb.NewChainMakerCertApplyClient(conn)

	// 调用服务

	var req pb.GetCertTarReq

	req.Filetarget = "./crypto-config/chainmaker-cert.tar.gz"
	req.Filesource = "./crypto-config/chainmaker"

	resp, err := client.GetCertTar(context.Background(), &req)

	if err != nil {

		log.Fatalf("resp error: %v\n", err)

	}

	fmt.Printf("Recevied: %v\n", resp)

}
func TestGenerateChainMakerCert(t *testing.T) {
	conn, err := grpc.Dial(":2333", grpc.WithInsecure())

	if err != nil {

		log.Fatalf("dial error: %v\n", err)

	}

	defer conn.Close()

	//实例化 UserInfoService 微服务的客户端

	client := pb.NewChainMakerCertApplyClient(conn)

	// 调用服务

	var req pb.ChainMakerCertApplyReq

	req.ChainId = "chain1"
	req.Filetarget = "./crypto-config/chainmaker"
	var org pb.Org
	org.OrgId = "wx-org5"
	org.Province = "Beijing"
	org.Country = "CN"
	org.Locality = "Beijing"
	var node1 pb.Node
	node1.NodeId = "common1"
	node1.Type = pb.NodeType_common
	node1.Sans = []string{"chainmaker.org"}
	var node2 pb.Node
	node2.NodeId = "consensus1"
	node2.Type = pb.NodeType_consensus
	node2.Sans = []string{"chainmaker.org"}
	org.Nodes = append(org.Nodes, &node1)
	org.Nodes = append(org.Nodes, &node2)
	var admin pb.User
	var user pb.User
	admin.UserName = "admin1"
	admin.Type = pb.UserType_admin
	org.Users = append(org.Users, &admin)
	req.Orgs = append(req.Orgs, &org)
	user.UserName = "user1"
	user.Type = pb.UserType_client
	org.Users = append(org.Users, &user)
	resp, err := client.GenerateCert(context.Background(), &req)
	if err != nil {

		log.Fatalf("resp error: %v\n", err)

	}

	fmt.Printf("Recevied: %v\n", resp)

}
