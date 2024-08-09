package model

import (
	"fmt"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type Server struct {
	Source        string
	Auth          bool
	AuthHeader    string `mapstructure:"auth_header"`
	AuthPassword  string `mapstructure:"auth_password"`
	DataType      uint32 `mapstructure:"data_type"`
	VersionSuffix string `mapstructure:"version_suffix"`
	FetchInterval uint32 `mapstructure:"fetch_interval"`
	SSH           SSHConfig
	Remote        string
	Password      string
	TLS           bool
	Insecure      bool
	ReportDelay   uint32 `mapstructure:"report_delay"`
}

type SSHConfig struct {
	Enabled  bool
	UseKey   bool `mapstructure:"use_key"`
	Host     string
	User     string
	Password string
	Key      string
}

type Config struct {
	Servers            map[string]Server
	Debug              bool
	IPQuery            bool   `mapstructure:"ip_query"`
	UseIPv6CountryCode bool   `mapstructure:"use_ipv6_country_code"`
	IPReportPeriod     uint32 `mapstructure:"ip_report_period"`
	DNS                []string
	v                  *viper.Viper
}

func (c *Config) Read(path string) error {
	c.v = viper.New()
	c.v.SetConfigFile(path)
	err := c.v.ReadInConfig()
	if err != nil {
		return err
	}

	err = c.v.Unmarshal(c)
	if err != nil {
		return err
	}

	for key, server := range c.Servers {
		if server.ReportDelay < 1 {
			server.ReportDelay = 1
		} else if server.ReportDelay > 4 {
			server.ReportDelay = 4
		}
		if strings.HasPrefix(server.SSH.Key, "~") {
			usr, err := user.Current()
			if err != nil {
				return fmt.Errorf("unable to get home dir: %v", err)
			}
			path := strings.Replace(server.SSH.Key, "~", usr.HomeDir, 1)
			server.SSH.Key, _ = filepath.Abs(path)
		}
		if server.VersionSuffix == "" {
			server.VersionSuffix = "-broker"
		}
		c.Servers[key] = server
	}

	if c.IPReportPeriod < 1 {
		c.IPReportPeriod = 1800
	}

	return nil
}
