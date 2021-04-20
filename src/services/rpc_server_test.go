package services

import (
	"context"
	"fmt"
	"log"
	"testing"

	pb "chainmaker.org/chainmaker-ca-backend/src/cmservice"
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

	req.Filetarget = "./crypto-config/chainmaker"
	var org pb.Org
	org.OrgId = "wx-org5"
	org.Province = "Beijing"
	org.Country = "CN"
	org.Locality = "Beijing"
	var node1 pb.Node
	node1.NodeId = "common1"
	node1.Type = pb.UserType_common
	node1.Sans = []string{"chainmaker.org"}
	var node2 pb.Node
	node2.NodeId = "consensus1"
	node2.Type = pb.UserType_consensus
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
func TestGetCert(t *testing.T) {
	conn, err := grpc.Dial(":2333", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("dial error: %v\n", err)
	}
	defer conn.Close()
	//实例化 UserInfoService 微服务的客户端
	client := pb.NewChainMakerCertApplyClient(conn)
	var getCertReq pb.GetCertReq
	getCertReq.OrgId = "wx-org1"
	getCertReq.Type = pb.UserType_admin
	getCertReq.Usage = pb.CertUsage_sign
	getCertReq.UserId = "admin"
	resp, err := client.GetCertByConditions(context.Background(), &getCertReq)
	if err != nil {
		fmt.Printf("err: %v", err.Error())
	}
	fmt.Println(resp)
}

func TestImportOrgCaAndKey(t *testing.T) {
	conn, err := grpc.Dial(":2333", grpc.WithInsecure())
	if err != nil {
		log.Fatalf("dial error: %v\n", err)
	}
	defer conn.Close()
	//实例化 UserInfoService 微服务的客户端
	client := pb.NewChainMakerCertApplyClient(conn)
	var getCertReq pb.ImportOrgCaAndKeyReq
	getCertReq.Cert = []byte("-----BEGIN CERTIFICATE-----\nMIICbzCCAhWgAwIBAgIDBin9MAoGCCqGSM49BAMCMGkxCzAJBgNVBAYTAkNOMRAw\nDgYDVQQIEwdCZWlqaW5nMRAwDgYDVQQHEwdCZWlqaW5nMRAwDgYDVQQKEwd3eC1y\nb290MQ0wCwYDVQQLEwRyb290MRUwEwYDVQQDEwxyb290Lnd4LXJvb3QwHhcNMjEw\nNDAxMTEyMTE4WhcNMjMwNDAxMTEyMTE4WjCBhjEOMAwGA1UEBhMFY2hpbmExDjAM\nBgNVBAgTBWNoaW5hMQ4wDAYDVQQHEwVjaGluYTEhMB8GA1UEChMYNjl2a2hreW9y\nZy5jbS05MWNwYXhzeDF0MQswCQYDVQQLEwJjYTEkMCIGA1UEAxMbY2EuNjl2a2hr\neW9yZy5jbS05MWNwYXhzeDF0MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE+App\nnhfo9B4CMv3CguYzvFfMfNlX3K5eBlI2ZU7fULevPNvpC1dYuwor0Fu6sje4o9vt\nKFDXJT/L2V0MMiIxgaOBjTCBijAOBgNVHQ8BAf8EBAMCAaYwDwYDVR0lBAgwBgYE\nVR0lADAPBgNVHRMBAf8EBTADAQH/MCkGA1UdDgQiBCBXkBjeYpSt4i8heG7BSARq\nHXsFSGFwG71h/uNFp+gc4zArBgNVHSMEJDAigCBawjOulmzCGvNcv9qoniBDc47o\ngptp5LMi45AyZyoOiDAKBggqhkjOPQQDAgNIADBFAiEA4noygx82uXCNsmrwM8BX\nyuKGlO2yfd5zOvaoYxKlvIgCIHI0d2MLiGNfp04uNfve0tw5SqaIgk00PQ48PRJO\nZWvt\n-----END CERTIFICATE-----\n")
	getCertReq.Key = []byte("-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEIKlb9ySwaqRw/oEgHwF1FJm014VXImsILQQnS4kas3N2oAoGCCqGSM49\nAwEHoUQDQgAE+Appnhfo9B4CMv3CguYzvFfMfNlX3K5eBlI2ZU7fULevPNvpC1dY\nuwor0Fu6sje4o9vtKFDXJT/L2V0MMiIxgQ==\n-----END EC PRIVATE KEY-----\n")
	resp, err := client.ImportOrgCaAndKey(context.Background(), &getCertReq)
	if err != nil {
		fmt.Printf("err: %v", err.Error())
	}
	fmt.Println(resp)
}
