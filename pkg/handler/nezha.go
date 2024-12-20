package handler

import (
	"github.com/uubulb/broker/model"
	pb "github.com/uubulb/broker/proto"
)

type TypeNezha struct {
	Host       *model.Host      `json:"host"`
	State      *model.HostState `json:"state"`
	ConfigName string           `json:"config_name"`
}

func (t *TypeNezha) GetHost() *model.Host {
	return t.Host
}

func (t *TypeNezha) GetState() *model.HostState {
	return t.State
}

func (t *TypeNezha) GetConfig() string {
	return t.ConfigName
}

func PB2DataNezha(d *pb.Data, name string) TypeNezha {
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
			Version:         h.GetVersion() + name,
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
		ConfigName: d.GetConfigName(),
	}
}
