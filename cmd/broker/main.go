package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nezhahq/service"
	"github.com/pkg/sftp"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/resolver"

	"github.com/uubulb/broker/model"
	"github.com/uubulb/broker/pkg/fm"
	"github.com/uubulb/broker/pkg/handler"
	"github.com/uubulb/broker/pkg/monitor"
	sshx "github.com/uubulb/broker/pkg/ssh"
	"github.com/uubulb/broker/pkg/util"
	pb "github.com/uubulb/broker/proto"
)

type BrokerParam struct {
	ConfigPath    string // 配置文件路径
	TempDir       string // 指定临时文件夹
	DisableSyslog bool   // 将日志输出到stderr
	Version       bool
}

var mainCmd = &cobra.Command{
	Use: "broker",
	Run: func(cmd *cobra.Command, args []string) {
		runService("", nil)
	},
	PreRun: preRun,
}

var (
	brokerParam  BrokerParam
	brokerConfig model.Config

	clientsMap     = xsync.NewMapOf[string, pb.NezhaServiceClient]()
	initializedMap = xsync.NewMapOf[string, bool]()
	sourcesMap     = xsync.NewMapOf[string, handler.Handler]()
)

const (
	delayWhenError = time.Second * 10
	networkTimeOut = time.Second * 5
)

const (
	_ uint8 = iota
	TypeHTTP
	TypeTCP
)

func init() {
	resolver.SetDefaultScheme("passthrough")
	net.DefaultResolver.PreferGo = true // 使用 Go 内置的 DNS 解析器解析域名
	net.DefaultResolver.Dial = func(ctx context.Context, network, address string) (net.Conn, error) {
		d := net.Dialer{
			Timeout: time.Second * 5,
		}
		dnsServers := util.DNSServersAll
		if len(brokerConfig.DNS) > 0 {
			dnsServers = brokerConfig.DNS
		}
		index := int(time.Now().Unix()) % int(len(dnsServers))
		queue := generateQueue(index, len(dnsServers))
		var conn net.Conn
		var err error
		for i := 0; i < len(queue); i++ {
			conn, err = d.DialContext(ctx, "udp", dnsServers[queue[i]])
			if err == nil {
				return conn, nil
			}
		}
		return nil, err
	}

	ex, err := os.Executable()
	if err != nil {
		panic(err)
	}

	mainCmd.PersistentFlags().StringVarP(&brokerParam.ConfigPath, "config", "c", "config.yml", "specify the configuration file")
	mainCmd.PersistentFlags().StringVar(&brokerParam.TempDir, "temp", "", "specify the temporary dir (default os.TempDir)")
	mainCmd.PersistentFlags().BoolVar(&brokerParam.DisableSyslog, "disable-syslog", false, "print log to stderr")
	mainCmd.PersistentFlags().BoolVarP(&brokerConfig.Debug, "debug", "d", false, "enable debug output")
	mainCmd.PersistentFlags().BoolVar(&brokerConfig.IPQuery, "ip-query", false, "enable IP query")
	mainCmd.PersistentFlags().BoolVar(&brokerConfig.UseIPv6CountryCode, "use-ipv6-countrycode", false, "use ipv6 address to lookup country code")
	mainCmd.Flags().BoolVarP(&brokerParam.Version, "version", "v", false, "Print version and exit")

	monitor.InitConfig(&brokerConfig)

	cobra.OnInitialize(func() {
		if !filepath.IsAbs(brokerParam.ConfigPath) {
			brokerParam.ConfigPath = filepath.Join(filepath.Dir(ex), brokerParam.ConfigPath)
		}
		brokerConfig.Read(brokerParam.ConfigPath)
	})
}

func main() {
	if err := mainCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func preRun(cmd *cobra.Command, args []string) {
	if brokerParam.Version {
		printVersion()
	}
}

func run() {
	// 更新IP信息
	if brokerConfig.IPQuery {
		go monitor.UpdateIP(brokerConfig.UseIPv6CountryCode, brokerConfig.IPReportPeriod)
	}

	done := make(chan struct{})
	monitor.StartTCPListener()

	for profile, config := range brokerConfig.Servers {
		monitor.GetServerConfig(profile, &config)

		go func(profile string, config model.Server) {
			for {
				var source handler.Handler
				var err error
				switch config.SourceType {
				case TypeHTTP:
					source, err = monitor.GetData(profile, config.DataType)
				case TypeTCP:
					source, err = monitor.GetDataTCP(profile, config.DataType)
				}
				if err != nil {
					initializedMap.Store(profile, false)
				} else {
					sourcesMap.Store(profile, source)
					initializedMap.Store(profile, true)
				}
				sleepDuration := time.Second
				if config.SourceType == TypeHTTP {
					sleepDuration = time.Second * time.Duration(config.FetchInterval)
					time.Sleep(time.Second * time.Duration(config.FetchInterval))
				}
				time.Sleep(sleepDuration)
			}
		}(profile, config)

		go func(profile string, config model.Server) {
			reportStateDaemon(profile, config)
		}(profile, config)

		go func(profile string, config model.Server) {
			for {
				if source, ok := sourcesMap.Load(profile); ok {
					conn := establish(config)
					client := pb.NewNezhaServiceClient(conn)
					clientsMap.Store(profile, client)

					if err := registerAndExecuteTasks(profile, client, source); err != nil {
						println("Error in registerAndExecuteTasks:", err)
						retry(profile, conn)
					}
				} else {
					time.Sleep(time.Second)
				}
			}
		}(profile, config)
	}

	<-done
}

func runService(action string, flags []string) {
	dir, err := os.Getwd()
	if err != nil {
		println("获取当前工作目录时出错: ", err)
		return
	}

	winConfig := map[string]interface{}{
		"OnFailure": "restart",
	}

	svcConfig := &service.Config{
		Name:             "nezha-broker",
		DisplayName:      "Broker",
		Description:      "Broker for Nezha",
		Arguments:        flags,
		WorkingDirectory: dir,
		Option:           winConfig,
	}

	prg := &program{
		exit: make(chan struct{}),
	}
	s, err := service.New(prg, svcConfig)
	if err != nil {
		log.Fatal("创建服务时出错: ", err)
	}
	prg.service = s

	errs := make(chan error, 5)
	if !brokerParam.DisableSyslog {
		util.Logger, err = s.Logger(errs)
		if err != nil {
			log.Fatal(err)
		}
	}

	go func() {
		for {
			err := <-errs
			if err != nil {
				log.Print(err)
			}
		}
	}()

	if action == "install" {
		initName := s.Platform()
		log.Println("Init system is:", initName)
	}

	if len(action) != 0 {
		err := service.Control(s, action)
		if err != nil {
			log.Fatal(err)
		}
		return
	}

	err = s.Run()
	if err != nil {
		util.Logger.Error(err)
	}
}

func establish(cfg model.Server) *grpc.ClientConn {
	auth := model.AuthHandler{
		ClientSecret: cfg.Password,
	}

	var securityOption grpc.DialOption
	if cfg.TLS {
		if cfg.Insecure {
			securityOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: true}))
		} else {
			securityOption = grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{MinVersion: tls.VersionTLS12}))
		}
	} else {
		securityOption = grpc.WithTransportCredentials(insecure.NewCredentials())
	}

	var conn *grpc.ClientConn
	var err error
	for {
		conn, err = grpc.NewClient(cfg.Remote, securityOption, grpc.WithPerRPCCredentials(&auth))
		if err != nil {
			printf("Connection fail: %s, retrying", err)
			time.Sleep(delayWhenError)
		} else {
			timeOutCtx, cancel := context.WithTimeout(context.Background(), networkTimeOut*2)
			err := func(conn *grpc.ClientConn, ctx context.Context) error {
				for {
					s := conn.GetState()
					switch s {
					case connectivity.Idle:
						conn.Connect()
					case connectivity.Ready:
						return nil
					case connectivity.Shutdown:
						return errors.New("connection closed")
					default:
					}
					if !conn.WaitForStateChange(ctx, s) {
						// ctx got timeout or canceled.
						return ctx.Err()
					}
				}
			}(conn, timeOutCtx)
			cancel()
			if err != nil {
				printf("Connection fail: %s, retrying", err)
				time.Sleep(delayWhenError)
				continue
			}
			break
		}
	}

	return conn
}

func retry(profile string, conn *grpc.ClientConn) {
	initializedMap.Store(profile, false)
	if conn != nil {
		conn.Close()
	}
	time.Sleep(delayWhenError)
}

func registerAndExecuteTasks(profile string, client pb.NezhaServiceClient, source handler.Handler) error {
	timeOutCtx, cancel := context.WithTimeout(context.Background(), networkTimeOut)
	defer cancel()

	host := source
	if _, err := client.ReportSystemInfo(timeOutCtx, host.GetHost().PB()); err != nil {
		return fmt.Errorf("上报系统信息失败：%w", err)
	}

	tasks, err := client.RequestTask(context.Background(), host.GetHost().PB())
	if err != nil {
		return fmt.Errorf("请求任务失败：%w", err)
	}

	return receiveTasks(profile, tasks)
}

func reportStateDaemon(profile string, cfg model.Server) {
	var lastReportHostInfo time.Time
	var err error
	defer println("reportState exit", time.Now(), "=>", err)
	for {
		// 为了更准确的记录时段流量，inited 后再上传状态信息
		if initialized, ok := initializedMap.Load(profile); initialized && ok {
			lastReportHostInfo = reportState(profile, lastReportHostInfo)
		} else {
			lastReportHostInfo = time.Time{}
		}
		time.Sleep(time.Second * time.Duration(cfg.ReportDelay))
	}
}

func reportState(profile string, lastReportHostInfo time.Time) time.Time {
	source, sOk := sourcesMap.Load(profile)
	client, cOk := clientsMap.Load(profile)
	if sOk && cOk {
		timeOutCtx, cancel := context.WithTimeout(context.Background(), networkTimeOut)
		_, err := client.ReportSystemState(timeOutCtx, source.GetState().PB())
		cancel()
		if err != nil {
			println("reportState error", err)
			time.Sleep(delayWhenError)
		}
		// 每10分钟发送一次硬件信息
		if lastReportHostInfo.Before(time.Now().Add(-10 * time.Minute)) {
			lastReportHostInfo = time.Now()
			host := source.GetHost()
			client.ReportSystemInfo(context.Background(), host.PB())
			if host.IP != "" {
				client.LookupGeoIP(context.Background(), &pb.GeoIP{Ip: host.IP})
			} else if brokerConfig.IPQuery && monitor.GeoQueryIP != "" {
				client.LookupGeoIP(context.Background(), &pb.GeoIP{Ip: monitor.GeoQueryIP})
			}
		}
	}

	return lastReportHostInfo
}

func receiveTasks(profile string, tasks pb.NezhaService_RequestTaskClient) error {
	var err error
	defer println("receiveTasks exit", time.Now(), "=>", err)
	for {
		var task *pb.Task
		task, err = tasks.Recv()
		if err != nil {
			return err
		}
		go func() {
			defer func() {
				if err := recover(); err != nil {
					println("task panic", task, err)
				}
			}()
			doTask(profile, task)
		}()
	}
}

func doTask(profile string, task *pb.Task) {
	var result pb.TaskResult
	result.Id = task.GetId()
	result.Type = task.GetType()
	switch task.GetType() {
	case model.TaskTypeHTTPGet:
		return // not implemented
	case model.TaskTypeICMPPing:
		return // not implemented
	case model.TaskTypeTCPPing:
		return // not implemented
	case model.TaskTypeCommand:
		handleCommandTask(profile, task, &result)
	case model.TaskTypeUpgrade:
		return
	case model.TaskTypeTerminalGRPC:
		handleTerminalTask(profile, task)
		return
	case model.TaskTypeNAT:
		return // not implemented
	case model.TaskTypeReportHostInfo:
		reportState(profile, time.Time{})
		return
	case model.TaskTypeFM:
		handleFMTask(profile, task)
		return
	case model.TaskTypeKeepalive:
		return
	default:
		println("task not supported: ", task)
		return
	}
	client, _ := clientsMap.Load(profile)
	client.ReportTask(context.Background(), &result)
}

func handleCommandTask(profile string, task *pb.Task, result *pb.TaskResult) {
	sc := brokerConfig.Servers[profile].SSH
	if !sc.Enabled {
		result.Data = "此 Agent 已禁止命令执行"
		return
	}
	startedAt := time.Now()
	var cmd string
	var endCh = make(chan struct{})
	timeout := time.NewTimer(time.Hour * 2)
	if util.IsWindows() {
		cmd = fmt.Sprintf("cmd /c '%s'", task.GetData())
	} else {
		cmd = fmt.Sprintf("sh -c '%s'", task.GetData())
	}
	go func() {
		select {
		case <-timeout.C:
			result.Data = "任务执行超时\n"
			close(endCh)
		case <-endCh:
			timeout.Stop()
		}
	}()
	s, err := sshx.NewSSH(&sc)
	if err != nil {
		result.Data += err.Error()
		result.Delay = float32(time.Since(startedAt).Seconds())
		return
	}

	output, err := s.ExecuteCommand(cmd)
	if err != nil {
		result.Data += fmt.Sprintf("%s\n%s", string(output), err.Error())
	} else {
		close(endCh)
		result.Data = string(output)
		result.Successful = true
	}

	result.Delay = float32(time.Since(startedAt).Seconds())
}

type WindowSize struct {
	Cols uint32
	Rows uint32
}

func handleTerminalTask(profile string, task *pb.Task) {
	sc := brokerConfig.Servers[profile].SSH
	if !sc.Enabled {
		println("此 Agent 已禁止命令执行")
		return
	}
	var terminal model.TerminalTask
	err := util.Json.Unmarshal([]byte(task.GetData()), &terminal)
	if err != nil {
		println("Terminal 任务解析错误：", err)
		return
	}

	client, _ := clientsMap.Load(profile)
	remoteIO, err := client.IOStream(context.Background())
	if err != nil {
		println("Terminal IOStream失败：", err)
		return
	}

	// 发送 StreamID
	if err := remoteIO.Send(&pb.IOStreamData{Data: append([]byte{
		0xff, 0x05, 0xff, 0x05,
	}, []byte(terminal.StreamID)...)}); err != nil {
		println("Terminal 发送StreamID失败：", err)
		return
	}

	s, err := sshx.NewSSH(&sc)
	if err != nil {
		println("Terminal SSH建立连接失败")
		return
	}

	tty, setSize, err := s.Redirect()
	if err != nil {
		println("Terminal s.Redirect失败：", err)
		return
	}
	s.Session.Shell()

	defer func() {
		err := tty.Close()
		errCloseSend := remoteIO.CloseSend()
		println("terminal exit: ", terminal.StreamID, err, errCloseSend)
		s.Session.Close()
		s.Client.Close()
	}()
	println("terminal init: ", terminal.StreamID)

	go func() {
		for {
			buf := make([]byte, 10240)
			read, err := tty.Read(buf)
			if err != nil {
				remoteIO.Send(&pb.IOStreamData{Data: []byte(err.Error())})
				remoteIO.CloseSend()
				return
			}
			remoteIO.Send(&pb.IOStreamData{Data: buf[:read]})
		}
	}()

	for {
		var remoteData *pb.IOStreamData
		if remoteData, err = remoteIO.Recv(); err != nil {
			return
		}
		if len(remoteData.Data) == 0 {
			return
		}
		switch remoteData.Data[0] {
		case 0:
			tty.Write(remoteData.Data[1:])
		case 1:
			decoder := util.Json.NewDecoder(strings.NewReader(string(remoteData.Data[1:])))
			var resizeMessage WindowSize
			err := decoder.Decode(&resizeMessage)
			if err != nil {
				continue
			}
			setSize(int(resizeMessage.Rows), int(resizeMessage.Cols))
		}
	}
}

func handleFMTask(profile string, task *pb.Task) {
	sc := brokerConfig.Servers[profile].SSH
	if !sc.Enabled {
		println("此 Agent 已禁止命令执行")
		return
	}

	var fmTask model.TaskFM
	err := util.Json.Unmarshal([]byte(task.GetData()), &fmTask)
	if err != nil {
		printf("FM 任务解析错误: %v", err)
		return
	}

	client, _ := clientsMap.Load(profile)
	remoteIO, err := client.IOStream(context.Background())
	if err != nil {
		println("Terminal IOStream失败：", err)
		return
	}

	// 发送 StreamID
	if err := remoteIO.Send(&pb.IOStreamData{Data: append([]byte{
		0xff, 0x05, 0xff, 0x05,
	}, []byte(fmTask.StreamID)...)}); err != nil {
		printf("FM 发送StreamID失败: %v", err)
		return
	}

	defer func() {
		errCloseSend := remoteIO.CloseSend()
		println("FM exit", fmTask.StreamID, nil, errCloseSend)
	}()
	println("FM init", fmTask.StreamID)

	s, err := sshx.NewSSH(&sc)
	if err != nil {
		remoteIO.Send(&pb.IOStreamData{Data: fm.CreateErr(err)})
		return
	}
	sfc, err := sftp.NewClient(s.Client)
	if err != nil {
		remoteIO.Send(&pb.IOStreamData{Data: fm.CreateErr(err)})
		return
	}
	defer sfc.Close()

	fmc := fm.NewFMClient(remoteIO, sfc, brokerParam.TempDir, printf)
	for {
		var remoteData *pb.IOStreamData
		if remoteData, err = remoteIO.Recv(); err != nil {
			return
		}
		if len(remoteData.Data) == 0 {
			return
		}
		fmc.DoTask(remoteData)
	}
}

func generateQueue(start int, size int) []int {
	var result []int
	for i := start; i < start+size; i++ {
		if i < size {
			result = append(result, i)
		} else {
			result = append(result, i-size)
		}
	}
	return result
}

func println(v ...interface{}) {
	util.Println(brokerConfig.Debug, v...)
}

func printf(format string, v ...interface{}) {
	util.Printf(brokerConfig.Debug, format, v...)
}
