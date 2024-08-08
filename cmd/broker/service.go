package main

import (
	"os"

	"github.com/nezhahq/service"
	"github.com/spf13/cobra"
)

type BrokerCliFlags struct {
	IsSpecified bool
	Flag        string
	Value       string
}

type program struct {
	exit    chan struct{}
	service service.Service
}

var serviceCmd = &cobra.Command{
	Use:   "service <install/uninstall/start/stop/restart>",
	Short: "configure system services",
	Args:  cobra.ExactArgs(1),
	Run:   serviceActions,
}

func (p *program) Start(s service.Service) error {
	go p.run()
	return nil
}

func (p *program) Stop(s service.Service) error {
	close(p.exit)
	if service.Interactive() {
		os.Exit(0)
	}
	return nil
}

func (p *program) run() {
	defer func() {
		if service.Interactive() {
			p.Stop(p.service)
		} else {
			p.service.Stop()
		}
	}()

	run()
}

func init() {
	mainCmd.AddCommand(serviceCmd)
}

func serviceActions(cmd *cobra.Command, args []string) {
	var brokerCliFlags []string

	flags := []BrokerCliFlags{
		{brokerParam.ConfigPath != "config.yml", "-c", brokerParam.ConfigPath},
		{brokerParam.DisableSyslog, "--disable-syslog", ""},
		{brokerConfig.Debug, "-d", ""},
		{brokerConfig.IPQuery, "--ip-query", ""},
		{brokerConfig.UseIPv6CountryCode, "--use-ipv6-countrycode", ""},
	}

	for _, f := range flags {
		if f.IsSpecified {
			if f.Value == "" {
				brokerCliFlags = append(brokerCliFlags, f.Flag)
			} else {
				brokerCliFlags = append(brokerCliFlags, f.Flag, f.Value)
			}
		}
	}

	action := args[0]
	runService(action, brokerCliFlags)
}
