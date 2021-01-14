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
	conn, err := grpc.Dial(":8972", grpc.WithInsecure())

	if err != nil {

		log.Fatalf("dial error: %v\n", err)

	}

	defer conn.Close()

	//实例化 UserInfoService 微服务的客户端

	client := pb.NewChainMakerCertApplyClient(conn)

	// 调用服务

	req := new(pb.GetCertTarReq)

	req.Filetarget = "./crypto-config/chainmaker-cert.tar.gz"

	resp, err := client.GetCertTar(context.Background(), req)

	if err != nil {

		log.Fatalf("resp error: %v\n", err)

	}

	fmt.Printf("Recevied: %v\n", resp)

}
func TestGenerateChainMakerCert(t *testing.T) {
	conn, err := grpc.Dial(":8972", grpc.WithInsecure())

	if err != nil {

		log.Fatalf("dial error: %v\n", err)

	}

	defer conn.Close()

	//实例化 UserInfoService 微服务的客户端

	client := pb.NewChainMakerCertApplyClient(conn)

	// 调用服务

	req := new(pb.ChainMakerCertApplyReq)

	req.ChainId = "chain1"
	var org pb.Org
	org.UserId = 1
	org.Province = "Beijing"
	org.Country = "CN"
	org.Locality = "Beijing"
	org.Organization = "wx-org1.chainmaker.org"
	org.OrganizationUnit = "ca"
	org.CommonName = "wx-org1.chainmaker.org"
	var node1 pb.Node
	node1.NodeName = "common1"
	node1.Sans = []string{"192.168.1.10"}
	var node2 pb.Node
	node2.NodeName = "consensus1"
	node2.Sans = []string{"192.168.1.11"}
	org.Nodes = append(org.Nodes, &node1)
	org.Nodes = append(org.Nodes, &node2)
	req.Orgs = append(req.Orgs, &org)
	resp, err := client.GenerateCert(context.Background(), req)

	if err != nil {

		log.Fatalf("resp error: %v\n", err)

	}

	fmt.Printf("Recevied: %v\n", resp)

}
