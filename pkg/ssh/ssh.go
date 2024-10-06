package ssh

import (
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"

	"github.com/uubulb/broker/model"
	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/knownhosts"
)

var (
	defaultKnownHost = filepath.Join(os.Getenv("HOME"), ".ssh", "known_hosts")
)

type SSH struct {
	Client  *ssh.Client
	Session *ssh.Session

	config *model.SSHConfig
}

func NewSSH(c *model.SSHConfig) (*SSH, error) {
	s := &SSH{config: c}
	if err := s.createConn(); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *SSH) createConn() error {
	var authConfig ssh.AuthMethod
	if s.config.UseKey {
		key, err := os.ReadFile(s.config.Key)
		if err != nil {
			return fmt.Errorf("unable to read private key: %v", err)
		}
		signer, err := ssh.ParsePrivateKey(key)
		if err != nil {
			return fmt.Errorf("unable to parse private key: %v", err)
		}
		authConfig = ssh.PublicKeys(signer)
	} else {
		authConfig = ssh.Password(s.config.Password)
	}

	var keyErr *knownhosts.KeyError
	config := &ssh.ClientConfig{
		User: s.config.User,
		Auth: []ssh.AuthMethod{authConfig},
		HostKeyCallback: ssh.HostKeyCallback(func(host string, remote net.Addr, pubKey ssh.PublicKey) error {
			kh := checkKnownHosts()
			hErr := kh(host, remote, pubKey)
			if errors.As(hErr, &keyErr) && len(keyErr.Want) > 0 {
				return keyErr
			} else if errors.As(hErr, &keyErr) && len(keyErr.Want) == 0 {
				return addHostKey(remote, pubKey)
			}
			return nil
		}),
	}

	var err error
	s.Client, err = ssh.Dial("tcp", s.config.Host, config)
	if err != nil {
		return fmt.Errorf("unable to create ssh client: %v", err)
	}
	return nil
}

func (s *SSH) ExecuteCommand(cmd string) ([]byte, error) {
	defer s.Client.Close()

	var err error
	s.Session, err = s.Client.NewSession()
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %v", err)
	}
	defer s.Session.Close()

	output, err := s.Session.CombinedOutput(cmd)
	if err != nil {
		return nil, fmt.Errorf("failed to execute command: %v", err)
	}
	return output, nil
}

func (s *SSH) Redirect() (io.ReadWriteCloser, func(h, w int), error) {
	var err error
	s.Session, err = s.Client.NewSession()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create session: %v", err)
	}

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := s.Session.RequestPty("xterm", 40, 80, modes); err != nil {
		return nil, nil, fmt.Errorf("request for pseudo terminal failed: %v", err)
	}

	stdin, err := s.Session.StdinPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get stdin pipe: %v", err)
	}

	stdout, err := s.Session.StdoutPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get stdout pipe: %v", err)
	}

	stderr, err := s.Session.StderrPipe()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get stderr pipe: %v", err)
	}

	tty := struct {
		io.Reader
		io.WriteCloser
	}{
		Reader:      io.MultiReader(stdout, stderr),
		WriteCloser: stdin,
	}

	setsize := func(h, w int) {
		s.Session.WindowChange(h, w)
	}
	return tty, setsize, nil
}

// https://cyruslab.net/2020/10/23/golang-how-to-write-ssh-hostkeycallback/
func createKnownHosts() {
	f, err := os.OpenFile(defaultKnownHost, os.O_CREATE, 0600)
	if err != nil {
		log.Fatalf("unable to create known_hosts: %v", err)
	}
	f.Close()
}

func checkKnownHosts() ssh.HostKeyCallback {
	createKnownHosts()
	kh, err := knownhosts.New(defaultKnownHost)
	if err != nil {
		log.Fatalf("unable to open known_hosts: %v", err)
	}
	return kh
}

func addHostKey(remote net.Addr, pubKey ssh.PublicKey) error {
	// add host key if host is not found in known_hosts, error object is return, if nil then connection proceeds,
	// if not nil then connection stops.
	khFilePath := defaultKnownHost

	f, err := os.OpenFile(khFilePath, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer f.Close()

	knownHosts := knownhosts.Normalize(remote.String())
	_, err = f.WriteString(knownhosts.Line([]string{knownHosts}, pubKey))
	return err
}
