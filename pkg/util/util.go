package util

import (
	"fmt"
	"os"
	"time"

	jsoniter "github.com/json-iterator/go"
	"github.com/nezhahq/service"
)

var (
	Json                  = jsoniter.ConfigCompatibleWithStandardLibrary
	Logger service.Logger = service.ConsoleLogger

	DNSServersV4  = []string{"8.8.8.8:53", "8.8.4.4:53", "1.1.1.1:53", "1.0.0.1:53"}
	DNSServersV6  = []string{"[2001:4860:4860::8888]:53", "[2001:4860:4860::8844]:53", "[2606:4700:4700::1111]:53", "[2606:4700:4700::1001]:53"}
	DNSServersAll = append(DNSServersV4, DNSServersV6...)
)

func IsWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}

func Println(enabled bool, v ...interface{}) {
	if enabled {
		Logger.Infof("BROKER@%s>> %v", time.Now().Format("2006-01-02 15:04:05"), fmt.Sprint(v...))
	}
}

func Printf(enabled bool, format string, v ...interface{}) {
	if enabled {
		Logger.Infof("BROKER@%s>> "+format, append([]interface{}{time.Now().Format("2006-01-02 15:04:05")}, v...)...)
	}
}

func RotateQueue1(start, i, size int) int {
	return (start + i) % size
}
