package handler

import (
	"github.com/uubulb/broker/model"
	pb "github.com/uubulb/broker/proto"
)

type TypeNezha struct {
	Host  *model.Host      `json:"host"`
	State *model.HostState `json:"state"`
}

func (t *TypeNezha) GetHost() *model.Host {
	return t.Host
}

func (t *TypeNezha) GetState() *model.HostState {
	return t.State
}

func PB2DataNezha(d *pb.Data) TypeNezha {
	h := d.GetHost()
	s := d.GetState()

	var ts []model.SensorTemperature
	for _, t := range s.GetTemperatures() {
		ts = append(ts, model.SensorTemperature{
			Name:        t.GetName(),
			Temperature: t.GetTemperature(),
		})
	}

	return TypeNezha{
		Host: &model.Host{
			Platform:        h.GetPlatform(),
			PlatformVersion: h.GetPlatformVersion(),
			CPU:             h.GetCpu(),
			MemTotal:        h.GetMemTotal(),
			DiskTotal:       h.GetDiskTotal(),
			SwapTotal:       h.GetSwapTotal(),
			Arch:            h.GetArch(),
			Virtualization:  h.GetVirtualization(),
			BootTime:        h.GetBootTime(),
			IP:              h.GetIp(),
			CountryCode:     h.GetCountryCode(),
			Version:         h.GetVersion(),
			GPU:             h.GetGpu(),
		},
		State: &model.HostState{
			CPU:            s.GetCpu(),
			MemUsed:        s.GetMemUsed(),
			SwapUsed:       s.GetSwapUsed(),
			DiskUsed:       s.GetDiskUsed(),
			NetInTransfer:  s.GetNetInTransfer(),
			NetOutTransfer: s.GetNetOutTransfer(),
			NetInSpeed:     s.GetNetInSpeed(),
			NetOutSpeed:    s.GetNetOutSpeed(),
			Uptime:         s.GetUptime(),
			Load1:          s.GetLoad1(),
			Load5:          s.GetLoad5(),
			Load15:         s.GetLoad15(),
			TcpConnCount:   s.GetTcpConnCount(),
			UdpConnCount:   s.GetUdpConnCount(),
			ProcessCount:   s.GetProcessCount(),
			Temperatures:   ts,
			GPU:            s.GetGpu(),
		},
	}
}
