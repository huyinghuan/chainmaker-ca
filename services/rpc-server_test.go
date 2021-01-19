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
	org.OrgId = "wx-org7"
	org.UserId = "admin"
	org.Province = "Beijing"
	org.Country = "CN"
	org.Locality = "Beijing"
	var node1 pb.Node
	node1.NodeId = "common1"
	node1.Sans = []string{"192.168.1.10"}
	var node2 pb.Node
	node2.NodeId = "consensus1"
	node2.Sans = []string{"192.168.1.11"}
	org.Nodes = append(org.Nodes, &node1)
	org.Nodes = append(org.Nodes, &node2)
	org.Users = []string{"user1", "user2"}
	req.Orgs = append(req.Orgs, &org)
	resp, err := client.GenerateCert(context.Background(), &req)
	if err != nil {

		log.Fatalf("resp error: %v\n", err)

	}

	fmt.Printf("Recevied: %v\n", resp)

}
