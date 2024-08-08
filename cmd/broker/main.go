package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/uubulb/broker/model"
	"github.com/uubulb/broker/pkg/handler"
	"github.com/uubulb/broker/pkg/monitor"
	sshx "github.com/uubulb/broker/pkg/ssh"
	"github.com/uubulb/broker/pkg/util"
	pb "github.com/uubulb/broker/proto"

	"github.com/nezhahq/service"
	"github.com/spf13/cobra"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/keepalive"
)

type BrokerParam struct {
	ConfigPath    string // 配置文件路径
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
	brokerParam    BrokerParam
	brokerConfig   model.Config
	clientsMap     sync.Map
	initializedMap sync.Map
	sourcesMap     sync.Map
)

const (
	delayWhenError = time.Second * 10
	networkTimeOut = time.Second * 5
)

func init() {
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
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// 更新IP信息
	if brokerConfig.IPQuery {
		go monitor.UpdateIP(brokerConfig.UseIPv6CountryCode, brokerConfig.IPReportPeriod)
	}

	done := make(chan struct{})

	// 捕获 INT, TERM 信号
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, os.Interrupt, syscall.SIGTERM)
		<-c
		log.Println("Received interrupt signal, cancelling...")
		cancel()
		close(done)
	}()

	for profile, config := range brokerConfig.Servers {
		monitor.GetServerConfig(&config)

		go func(profile string, config model.Server) {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					source, err := monitor.GetData(config.DataType)
					if err != nil {
						println("failed to fetch data from source: ", err)
					} else {
						sourcesMap.Store(profile, &source)
					}
					time.Sleep(time.Second * time.Duration(config.FetchInterval))
				}
			}
		}(profile, config)

		go func(profile string, config model.Server) {
			reportStateDaemon(profile, config)
		}(profile, config)

		go func(profile string, config model.Server) {
			for {
				select {
				case <-ctx.Done():
					return
				default:
					if source, ok := sourcesMap.Load(profile); ok {
						conn := establish(config)
						client := pb.NewNezhaServiceClient(conn)
						clientsMap.Store(profile, &client)

						if err := registerAndExecuteTasks(ctx, profile, client, source.(*handler.Handler)); err != nil {
							println("Error in registerAndExecuteTasks:", err)
							retry(profile, conn)
						}
					}
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

	keepaliveOptions := &keepalive.ClientParameters{
		Timeout: networkTimeOut,
	}

	var conn *grpc.ClientConn
	var err error
	for {
		conn, err = grpc.NewClient(cfg.Remote, securityOption, grpc.WithKeepaliveParams(*keepaliveOptions), grpc.WithPerRPCCredentials(&auth))
		if err != nil {
			println("Connection fail, retrying: ", err)
			time.Sleep(delayWhenError)
		} else {
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

func registerAndExecuteTasks(ctx context.Context, profile string, client pb.NezhaServiceClient, source *handler.Handler) error {
	timeOutCtx, cancel := context.WithTimeout(ctx, networkTimeOut)
	defer cancel()

	host := *source
	if _, err := client.ReportSystemInfo(timeOutCtx, host.GetHost().PB()); err != nil {
		return fmt.Errorf("上报系统信息失败：%w", err)
	}
	initializedMap.Store(profile, true)

	tasks, err := client.RequestTask(ctx, host.GetHost().PB())
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
		lastReportHostInfo = reportState(profile, lastReportHostInfo)
		time.Sleep(time.Second * time.Duration(cfg.ReportDelay))
	}
}

func reportState(profile string, lastReportHostInfo time.Time) time.Time {
	sourceI, sOk := sourcesMap.Load(profile)
	clientI, cOk := clientsMap.Load(profile)
	_, iOk := initializedMap.Load(profile)
	if sOk && cOk && iOk {
		timeOutCtx, cancel := context.WithTimeout(context.Background(), networkTimeOut)
		source := *sourceI.(*handler.Handler)
		client := *clientI.(*pb.NezhaServiceClient)
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
	case model.TaskTypeKeepalive:
		return
	default:
		println("task not supported: ", task)
		return
	}
	clientI, _ := clientsMap.Load(profile)
	client := *clientI.(*pb.NezhaServiceClient)
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
	s := &sshx.SSH{Config: sc}
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

	clientI, _ := clientsMap.Load(profile)
	client := *clientI.(*pb.NezhaServiceClient)
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

	s := &sshx.SSH{Config: sc}
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
		if remoteData.Data == nil || len(remoteData.Data) == 0 {
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
