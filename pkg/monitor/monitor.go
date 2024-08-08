package monitor

import (
	"fmt"
	"io"
	"net/http"

	"github.com/uubulb/broker/model"
	"github.com/uubulb/broker/pkg/handler"
	"github.com/uubulb/broker/pkg/util"
	pb "github.com/uubulb/broker/proto"

	"google.golang.org/protobuf/proto"
)

var (
	serverConfig *model.Server
	brokerConfig *model.Config
	httpClient   = &http.Client{}
)

const (
	_ uint32 = iota
	TypeNezha
	TypeNezhaJSON
)

func InitConfig(cfg *model.Config) {
	brokerConfig = cfg
}

func GetServerConfig(cfg *model.Server) {
	serverConfig = cfg
}

func GetData(dataType uint32) (handler.Handler, error) {
	url := serverConfig.Source
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	if serverConfig.Auth {
		req.Header.Add(serverConfig.AuthHeader, serverConfig.AuthPassword)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	switch dataType {
	case TypeNezha:
		pbData := &pb.Data{}
		err = proto.Unmarshal(data, pbData)
		if err != nil {
			return nil, err
		}
		stats := handler.PB2DataNezha(pbData)
		return &stats, nil
	case TypeNezhaJSON:
		stats := &handler.TypeNezha{}
		err = util.Json.Unmarshal(data, stats)
		if err != nil {
			return nil, err
		}
		return stats, nil
	}

	return nil, fmt.Errorf("error getting data from source")
}
