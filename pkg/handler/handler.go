package handler

import "github.com/uubulb/broker/model"

type Handler interface {
	GetHost() *model.Host
	GetState() *model.HostState
}
