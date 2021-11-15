package main

import (
	"bytes"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/httputil"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	lru "github.com/hashicorp/golang-lru"
	"github.com/ulule/limiter"
	"github.com/ulule/limiter/drivers/middleware/stdlib"
	"github.com/ulule/limiter/drivers/store/memory"
	"go.uber.org/zap"
)

type ProxyServer struct {
	targetURL       *url.URL
	config          *ServerConfig
	log             *zap.Logger
	allowListRegex  []*regexp.Regexp
	blockListRegex  []*regexp.Regexp
	dontChanceRegex []*regexp.Regexp
	reverseProxy    *httputil.ReverseProxy
	cache           *lru.Cache
}

func NewProxyServer(targetURL *url.URL, config *ServerConfig, log *zap.Logger) *ProxyServer {
	proxyServer := ProxyServer{
		log:          log,
		config:       config,
		targetURL:    targetURL,
		reverseProxy: httputil.NewSingleHostReverseProxy(targetURL),
	}
	return &proxyServer
}

func (p *ProxyServer) Start() {
	setupRegexp(p)

	server := http.Server{
		Addr:         ":" + strconv.Itoa(p.config.ServerPort),
		ReadTimeout:  time.Duration(p.config.ReadTimeout) * time.Second,
		WriteTimeout: time.Duration(p.config.WriteTimeout) * time.Second,
		IdleTimeout:  time.Duration(p.config.IdleTimeout) * time.Second,
	}

	rateLimitMiddleware := createRateLimitMiddleware(
		p.config.RateLimitCount,
		p.config.RateLimitPeriod,
	)

	mainHandler := rateLimitMiddleware.Handler(http.HandlerFunc(handle(p)))

	http.Handle("/", mainHandler)

	server.ListenAndServe()
}

func createRateLimitMiddleware(count int64, period int) *stdlib.Middleware {

	rate := limiter.Rate{
		Period: time.Duration(period) * time.Second,
		Limit:  count,
	}

	store := memory.NewStore()

	middleware := stdlib.NewMiddleware(
		limiter.New(store, rate),
		stdlib.WithForwardHeader(true),
	)

	return middleware
}

func handle(p *ProxyServer) func(w http.ResponseWriter, req *http.Request) {
	return func(w http.ResponseWriter, req *http.Request) {
		logRequest(p, req)

		tezresponse := []byte(string("Call blocklisted"))

		if p.isAllowed(req.URL.Path) {

			if req.Method == "GET" && p.isCacheable(req.URL.Path) {
				if val, ok := p.cache.Get(req.URL.Path); ok {
					tezresponse = val.([]byte)
				} else {
					tezresponse = p.GetTezosResponse(req.URL.Path, "")
					p.cache.Add(req.URL.Path, tezresponse)
				}
				optionsHeaders(w)
				fmt.Fprint(w, string(tezresponse))

			} else {
				p.reverseProxy.ServeHTTP(w, req)
			}

		} else {
			fmt.Fprint(w, string(tezresponse))
		}
	}
}

func (p *ProxyServer) GetTezosResponse(url, args string) []byte {
	url = "http://" + p.targetURL.Host + url
	var jsonStr = []byte(args)
	req, err := http.NewRequest("GET", url, bytes.NewBuffer(jsonStr))
	if err != nil {
		p.log.Error("Error sending GET to Tezos" + err.Error())
	}
	client := &http.Client{
		Timeout: time.Duration(p.config.ReadTimeout) * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	resp, err := client.Do(req)
	var b []byte
	b, err = ioutil.ReadAll(resp.Body)
	if err != nil {
		p.log.Error("Error getting Response from the tezos Node: " + err.Error())
	}
	resp.Body.Close()
	return b
}

// client := &http.Client{
// 	Timeout: clientTimeout,
// 	Transport: trace.HTTPTransport(&http.Transport{
// 		Dial:                  dialer.Dial(),
// 		DialContext:           dialer.DialContext(),
// 		TLSHandshakeTimeout:   tlsHandshakeTimeout,
// 		ResponseHeaderTimeout: responseHeaderTimeout,
// 		ExpectContinueTimeout: time.Second,
// 		MaxIdleConns:          int(maxIdleConns),
// 		DisableCompression:    true,
// 	}),
// 	CheckRedirect: func(req *http.Request, via []*http.Request) error {
// 		return http.ErrUseLastResponse
// 	},
// }

// response, err := h.client().Do(request)

//Got a response? Close it!
// 	if response != nil && response.Body != nil {
// 		defer func() {
// 			io.Copy(ioutil.Discard, response.Body)
// 			response.Body.Close()
// 		}()
// }

func (p *ProxyServer) isAllowed(url string) bool {
	ret := false
	urls := strings.Split(url, "?")
	url = "/" + strings.Trim(urls[0], "/")
	// for _,wl := range p.whitelistedR {
	// 	if wl.Match([]byte(url)) {
	// 		ret = true
	// 		for _, bl := range p.blacklsitedR {
	// 			if bl.Match([]byte(url)) {
	// 				ret = false
	// 				break
	// 			}
	// 		}
	// 		break
	// 	}
	// }
	return ret
}

func setupRegexp(p *ProxyServer) {
	for _, s := range p.config.Blocklist {
		regex, err := regexp.Compile(s)
		if err != nil {
			p.log.Error("Cant compile Regexp: " + s)
		} else {
			p.blockListRegex = append(p.blockListRegex, regex)
		}
	}
	for _, s := range p.config.Allowlist {
		regex, err := regexp.Compile(s)
		if err != nil {
			p.log.Error("Cant compile Regexp: " + s)
		} else {
			p.allowListRegex = append(p.allowListRegex, regex)
		}
	}
	for _, s := range p.config.DontCache {
		regex, err := regexp.Compile(s)
		if err != nil {
			p.log.Error("Cant compile Regexp: " + s)
		} else {
			p.dontChanceRegex = append(p.dontChanceRegex, regex)
		}
	}
}

func (this *ProxyServer) isCacheable(url string) bool {
	ret := true
	// for _,wl := range this.dontCacheR {
	// 	if wl.Match([]byte(url)) {
	// 		ret = false
	// 	}
	// }
	return ret
}

func logRequest(p *ProxyServer, req *http.Request) {
	p.log.Info("Incoming Request",
		zap.String("remote_addr", req.RemoteAddr),
		zap.String("user_agent", req.UserAgent()),
	)
}

func optionsHeaders(w http.ResponseWriter) {
	w.Header().Set("Allow", "OPTIONS, POST")
	w.Header().Set("Accept", "application/json")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Depth, User-Agent, X-File-Size, X-Requested-With, If-Modified-Since, X-File-Name, Cache-Control")
	w.Header().Set("Access-Control-Allow-Methods", "POST")
	w.Header().Set("Content-Type", "application/json")
}
