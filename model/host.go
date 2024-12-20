package model

import (
	pb "github.com/uubulb/broker/proto"
)

type SensorTemperature struct {
	Name        string  `json:"name"`
	Temperature float64 `json:"temperature"`
}

type HostState struct {
	CPU            float64             `json:"cpu"`
	MemUsed        uint64              `json:"mem_used"`
	SwapUsed       uint64              `json:"swap_used"`
	DiskUsed       uint64              `json:"disk_used"`
	NetInTransfer  uint64              `json:"net_in_transfer"`
	NetOutTransfer uint64              `json:"net_out_transfer"`
	NetInSpeed     uint64              `json:"net_in_speed"`
	NetOutSpeed    uint64              `json:"net_out_speed"`
	Uptime         uint64              `json:"uptime"`
	Load1          float64             `json:"load1"`
	Load5          float64             `json:"load5"`
	Load15         float64             `json:"load15"`
	TcpConnCount   uint64              `json:"tcp_conn_count"`
	UdpConnCount   uint64              `json:"udp_conn_count"`
	ProcessCount   uint64              `json:"process_count"`
	Temperatures   []SensorTemperature `json:"temperatures"`
	GPU            []float64           `json:"gpu"`
}

func (s *HostState) PB() *pb.State {
	var ts []*pb.State_SensorTemperature
	for _, t := range s.Temperatures {
		ts = append(ts, &pb.State_SensorTemperature{
			Name:        t.Name,
			Temperature: t.Temperature,
		})
	}

	return &pb.State{
		Cpu:            s.CPU,
		MemUsed:        s.MemUsed,
		SwapUsed:       s.SwapUsed,
		DiskUsed:       s.DiskUsed,
		NetInTransfer:  s.NetInTransfer,
		NetOutTransfer: s.NetOutTransfer,
		NetInSpeed:     s.NetInSpeed,
		NetOutSpeed:    s.NetOutSpeed,
		Uptime:         s.Uptime,
		Load1:          s.Load1,
		Load5:          s.Load5,
		Load15:         s.Load15,
		TcpConnCount:   s.TcpConnCount,
		UdpConnCount:   s.UdpConnCount,
		ProcessCount:   s.ProcessCount,
		Temperatures:   ts,
		Gpu:            s.GPU,
	}
}

type Host struct {
	Platform        string   `json:"platform"`
	PlatformVersion string   `json:"platform_version"`
	CPU             []string `json:"cpu"`
	MemTotal        uint64   `json:"mem_total"`
	DiskTotal       uint64   `json:"disk_total"`
	SwapTotal       uint64   `json:"swap_total"`
	Arch            string   `json:"arch"`
	Virtualization  string   `json:"virtualization"`
	BootTime        uint64   `json:"boot_time"`
	Version         string   `json:"version"`
	GPU             []string `json:"gpu"`
}

func (h *Host) PB() *pb.Host {
	return &pb.Host{
		Platform:        h.Platform,
		PlatformVersion: h.PlatformVersion,
		Cpu:             h.CPU,
		MemTotal:        h.MemTotal,
		DiskTotal:       h.DiskTotal,
		SwapTotal:       h.SwapTotal,
		Arch:            h.Arch,
		Virtualization:  h.Virtualization,
		BootTime:        h.BootTime,
		Version:         h.Version,
		Gpu:             h.GPU,
	}
}
