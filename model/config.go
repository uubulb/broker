package model

import (
	"fmt"
	"log"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/spf13/viper"
)

type Server struct {
	Source        string
	SourceType    uint8 `mapstructure:"source_type"`
	Auth          bool
	AuthHeader    string `mapstructure:"auth_header"`
	AuthPassword  string `mapstructure:"auth_password"`
	DataType      uint8  `mapstructure:"data_type"`
	VersionSuffix string `mapstructure:"version_suffix"`
	FetchInterval uint32 `mapstructure:"fetch_interval"`
	SSH           SSHConfig
	Remote        string
	AgentSecret   string `mapstructure:"agent_secret"`
	UUID          string
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
	Servers    map[string]Server `mapstructure:"servers"`
	Debug      bool              `mapstructure:"debug"`
	DNS        []string          `mapstructure:"dns"`
	ListenAddr string            `mapstructure:"listen_addr"`
	v          *viper.Viper
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
		if err := validateServer(&server); err != nil {
			log.Fatalf("server %s: %v", key, err)
		}
		c.Servers[key] = server
	}

	if c.ListenAddr == "" {
		return fmt.Errorf("listen_addr is required")
	}

	return nil
}

func validateServer(server *Server) error {
	// TypeHTTP
	if server.SourceType == 1 {
		if server.Source == "" {
			return fmt.Errorf("server.source is required")
		}
	}
	if server.SourceType == 0 {
		return fmt.Errorf("server.source_type is required")
	}
	if server.Remote == "" {
		return fmt.Errorf("server.remote is required")
	}
	if server.AgentSecret == "" {
		return fmt.Errorf("server.agent_secret is required")
	}
	if server.UUID == "" {
		return fmt.Errorf("server.uuid is required")
	}
	if server.ReportDelay < 1 {
		server.ReportDelay = 3
	} else if server.ReportDelay > 4 {
		server.ReportDelay = 4
	}
	if server.SSH.Enabled {
		if server.SSH.Host == "" {
			return fmt.Errorf("server.ssh.host is required")
		}
		if server.SSH.User == "" {
			return fmt.Errorf("server.ssh.user is required")
		}
		if server.SSH.UseKey {
			if server.SSH.Key != "" {
				if strings.HasPrefix(server.SSH.Key, "~") {
					usr, err := user.Current()
					if err != nil {
						return fmt.Errorf("unable to get home dir: %v", err)
					}
					path := strings.Replace(server.SSH.Key, "~", usr.HomeDir, 1)
					server.SSH.Key, _ = filepath.Abs(path)
				}
			} else {
				return fmt.Errorf("server.ssh.key is required")
			}
		} else {
			if server.SSH.Password == "" {
				return fmt.Errorf("server.ssh.password is required")
			}
		}
	}
	if server.VersionSuffix == "" {
		server.VersionSuffix = "-broker"
	}
	if server.DataType == 0 {
		return fmt.Errorf("server.data_type is required")
	}

	return nil
}
