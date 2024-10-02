package monitor

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"sync"

	"github.com/uubulb/broker/model"
	"github.com/uubulb/broker/pkg/handler"
	"github.com/uubulb/broker/pkg/util"
	pb "github.com/uubulb/broker/proto"

	"google.golang.org/protobuf/proto"
)

type tcpClient struct {
	conn net.Conn
	id   string
}

type bp struct {
	buf []byte
}

var bufPool = sync.Pool{
	New: func() any {
		return &bp{
			buf: make([]byte, 512),
		}
	},
}

var (
	serverConfig, tcpConns sync.Map
	brokerConfig           *model.Config
	httpClient             = &http.Client{}
	listener               net.Listener
)

const (
	_ uint32 = iota
	TypeNezha
	TypeNezhaJSON
)

func InitConfig(cfg *model.Config) {
	brokerConfig = cfg
}

func GetServerConfig(profile string, cfg *model.Server) {
	serverConfig.Store(profile, cfg)
}

func StartTCPListener() {
	go acceptConns()
}

func GetData(profile string, dataType uint32) (handler.Handler, error) {
	cfgI, ok := serverConfig.Load(profile)
	if ok {
		cfg := cfgI.(*model.Server)
		url := cfg.Source
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to create HTTP request: %v", err)
		}
		if cfg.Auth {
			req.Header.Add(cfg.AuthHeader, cfg.AuthPassword)
		}
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, fmt.Errorf("failed to perform HTTP request: %v", err)
		}
		defer resp.Body.Close()

		data, err := io.ReadAll(resp.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read HTTP response body: %v", err)
		}

		return processData(cfg, data, dataType)
	}

	return nil, fmt.Errorf("server config for profile %s not found", profile)
}

func GetDataTCP(profile string, dataType uint32) (handler.Handler, error) {
	data, err := receive(profile)
	if err != nil {
		return nil, fmt.Errorf("failed to receive TCP data: %v", err)
	}
	if cfgI, ok := serverConfig.Load(profile); ok {
		cfg := cfgI.(*model.Server)
		if len(data) > 0 {
			return processData(cfg, data, dataType)
		}
	}
	return nil, fmt.Errorf("server config for profile %s not found", profile)
}

func processData(cfg *model.Server, data []byte, dataType uint32) (handler.Handler, error) {
	switch dataType {
	case TypeNezha:
		pbData := &pb.Data{}
		err := proto.Unmarshal(data, pbData)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal Protobuf data: %v", err)
		}
		stats := handler.PB2DataNezha(pbData, cfg.VersionSuffix)
		return &stats, nil
	case TypeNezhaJSON:
		stats := &handler.TypeNezha{}
		err := util.Json.Unmarshal(data, stats)
		if err != nil {
			return nil, fmt.Errorf("failed to unmarshal JSON data: %v", err)
		}
		return stats, nil
	}
	return nil, fmt.Errorf("dataType %d not found", dataType)
}

func receive(profile string) ([]byte, error) {
	if clientI, ok := tcpConns.Load(profile); ok {
		client := clientI.(*tcpClient)
		data, err := read(client.conn)
		if err != nil {
			client.conn.Close()
			tcpConns.Delete(profile)
			return nil, err
		}
		return data, nil
	}
	return nil, fmt.Errorf("no TCP connection found for profile %s", profile)
}

func acceptConns() {
	var err error
	listener, err = listenTCP()
	if err != nil {
		println("Listen failed: ", err)
	}
	defer listener.Close()

	for {
		conn, err := listener.Accept()
		if err != nil {
			println("Failed to accept connection: ", err)
			continue
		}

		go handleConnection(conn)
	}
}

func handleConnection(conn net.Conn) {
	bin, err := read(conn)
	if err != nil {
		log.Printf("Failed to read from connection: %v", err)
		conn.Close()
		return
	}
	pbData := &pb.Data{}
	_ = proto.Unmarshal(bin, pbData)
	profile := pbData.GetConfigName()

	if clientI, ok := tcpConns.Load(profile); ok {
		existingClient := clientI.(*tcpClient)
		existingClient.conn.Close()
	}

	client := &tcpClient{conn: conn, id: profile}
	tcpConns.Store(profile, client)
}

func read(conn net.Conn) ([]byte, error) {
	bp := bufPool.Get().(*bp)
	defer bufPool.Put(bp)
	n, err := conn.Read(bp.buf)
	if err != nil {
		if err == io.EOF {
			return nil, fmt.Errorf("connection closed by peer")
		}
		return nil, fmt.Errorf("failed to read from connection: %v", err)
	}

	if n > 0 {
		return bp.buf[:n], nil
	}
	return nil, nil
}

func listenTCP() (net.Listener, error) {
	listener, err := net.Listen("tcp", brokerConfig.ListenAddr)
	if err != nil {
		return nil, fmt.Errorf("failed to start TCP listener: %v", err)
	}
	println("TCP server listening on ", brokerConfig.ListenAddr)
	return listener, nil
}

func println(v ...interface{}) {
	util.Println(brokerConfig.Debug, v...)
}
