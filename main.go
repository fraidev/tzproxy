package main

import (
	"net/url"
	"os"
	"os/signal"
	"strconv"
	"syscall"

	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func main() {
	// Setup logger
	logger, _ := zap.NewProduction()
	defer logger.Sync()

	// Setup environment variables
	viper := viper.New()
	viper.AddConfigPath(".")
	viper.SetConfigName("config")
	viper.ReadInConfig()

	// Set the targetURL
	targetURL := buildTargetURL(viper.GetString("tezos.host"), viper.GetInt("tezos.port"))

	// Load Server Config
	serverConfig := LoadServerConfig(viper)

	// Setup Proxy Server
	serverProxy := NewProxyServer(targetURL, serverConfig, logger)

	// Start Proxy Server
	serverProxy.Start()

	// Graceful Shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)
	<-done

	logger.Info("Server Stopped")
}

func buildTargetURL(tezosHost string, tezosPort int) *url.URL {
	targetURL, _ := url.Parse("http://" + tezosHost + ":" + strconv.Itoa(tezosPort))
	return targetURL
}

type Filter interface {
	Name() string
}

// type BeforeFilter interface {
// 	Filter
// 	BlacklistedHeaders() []string
// 	DoBefore(context context.Context) BeforeFilterError
// }

// type AfterFilter interface {
// 	Filter
// 	DoAfter(context context.Context) AfterFilterError
// }
