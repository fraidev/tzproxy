package main

import "github.com/spf13/viper"

type ServerConfig struct {
	RateLimitPeriod int
	ServerPort      int
	ReadTimeout     int
	WriteTimeout    int
	IdleTimeout     int
	CacheMaxItems   int
	RateLimitCount  int64
	DontCache       []string
	Allowlist       []string
	Blocklist       []string
}

func LoadServerConfig(vip *viper.Viper) *ServerConfig {
	return &ServerConfig{
		ServerPort:      vip.GetInt("server.port"),
		Allowlist:       vip.GetStringSlice("proxy.whitelistedMethods"),
		ReadTimeout:     vip.GetInt("server.readTimeout"),
		WriteTimeout:    vip.GetInt("proxy.writeTimeout"),
		IdleTimeout:     vip.GetInt("proxy.idleTimeout"),
		RateLimitCount:  vip.GetInt64("proxy.rateLimitCount"),
		RateLimitPeriod: vip.GetInt("proxy.rateLimitPeriod"),
		Blocklist:       vip.GetStringSlice("proxy.blockedMethods"),
		DontCache:       vip.GetStringSlice("proxy.dontCache"),
		CacheMaxItems:   vip.GetInt("proxy.cacheMaxItems"),
	}
}
