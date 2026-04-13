package main

/*
#include "turn-proxy.h"
#include <stdlib.h>

static void callProxyLoggerFn(proxy_logger_fn fn, void *ctx, int level, const char *msg) {
    fn(ctx, level, msg);
}

static void callProxyCaptchaFn(proxy_captcha_fn fn, void *ctx, const char *url, const char *session) {
    fn(ctx, url, session);
}
*/
import "C"
import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"
)

var (
	proxyMu       sync.Mutex
	proxyCancel   context.CancelFunc
	proxyReady    chan struct{}
	proxyWGConfig chan string
	proxyStats    *Stats

	proxyLoggerCtx unsafe.Pointer
	proxyLoggerFn  C.proxy_logger_fn

	proxyCaptchaCtx unsafe.Pointer
	proxyCaptchaFn  C.proxy_captcha_fn
)

// logBridge перехватывает стандартный log.Printf и отправляет в iOS
type logBridge struct{}

func (logBridge) Write(p []byte) (int, error) {
	msg := strings.TrimRight(string(p), "\n")
	if proxyLoggerFn != nil {
		cmsg := C.CString(msg)
		C.callProxyLoggerFn(proxyLoggerFn, proxyLoggerCtx, C.int(0), cmsg)
		C.free(unsafe.Pointer(cmsg))
	}
	return len(p), nil
}

func proxyLog(level int, format string, args ...interface{}) {
	msg := fmt.Sprintf(format, args...)
	if proxyLoggerFn != nil {
		cmsg := C.CString(msg)
		C.callProxyLoggerFn(proxyLoggerFn, proxyLoggerCtx, C.int(level), cmsg)
		C.free(unsafe.Pointer(cmsg))
	}
}

func requestCaptcha(url, sessionToken string) string {
	if proxyCaptchaFn == nil {
		return ""
	}

	captchaToken := make(chan string, 1)

	// Сохраняем канал глобально для ProxyResolveCaptcha
	proxyCaptchaCh = captchaToken

	curl := C.CString(url)
	csess := C.CString(sessionToken)
	C.callProxyCaptchaFn(proxyCaptchaFn, proxyCaptchaCtx, curl, csess)
	C.free(unsafe.Pointer(curl))
	C.free(unsafe.Pointer(csess))

	select {
	case token := <-captchaToken:
		return token
	case <-proxyCtx.Done():
		return ""
	}
}

var (
	proxyCaptchaCh chan string
	proxyCtx       context.Context
)

//export ProxySetLogger
func ProxySetLogger(ctx unsafe.Pointer, fn C.proxy_logger_fn) {
	proxyLoggerCtx = ctx
	proxyLoggerFn = fn
}

//export ProxySetCaptchaHandler
func ProxySetCaptchaHandler(ctx unsafe.Pointer, fn C.proxy_captcha_fn) {
	proxyCaptchaCtx = ctx
	proxyCaptchaFn = fn
}

//export ProxyResolveCaptcha
func ProxyResolveCaptcha(token *C.char) {
	if proxyCaptchaCh != nil {
		select {
		case proxyCaptchaCh <- C.GoString(token):
		default:
		}
	}
}

//export ProxyStart
func ProxyStart(cfg *C.ProxyConfig) {
	proxyMu.Lock()
	defer proxyMu.Unlock()

	if proxyCancel != nil {
		return
	}

	proxyReady = make(chan struct{})

	vkLink := C.GoString(cfg.vkLink)
	vkLink2 := C.GoString(cfg.vkLink2)
	peerAddr := C.GoString(cfg.peerAddr)
	listenAddr := C.GoString(cfg.listenAddr)
	connections := int(cfg.connections)
	useTCP := int(cfg.useTCP) != 0
	sni := C.GoString(cfg.sni)
	password := C.GoString(cfg.password)
	deviceID := C.GoString(cfg.deviceID)
	captchaModeStr := C.GoString(cfg.captchaMode)

	ctx, cancel := context.WithCancel(context.Background())
	proxyCancel = cancel
	proxyCtx = ctx

	go runProxy(ctx, proxyConfig{
		vkLink:      vkLink,
		vkLink2:     vkLink2,
		peerAddr:    peerAddr,
		listenAddr:  listenAddr,
		connections: connections,
		useTCP:      useTCP,
		sni:         sni,
		password:    password,
		deviceID:    deviceID,
		captchaMode: captchaModeStr,
	})
}

//export ProxyStop
func ProxyStop() {
	proxyMu.Lock()
	defer proxyMu.Unlock()

	if proxyCancel != nil {
		proxyCancel()
		proxyCancel = nil
	}
}

//export ProxyWaitReady
func ProxyWaitReady(timeoutMs C.int) C.int {
	if proxyReady == nil {
		return 0
	}

	select {
	case <-proxyReady:
		return 1
	case <-proxyCtx.Done():
		return 0
	}
}

//export ProxyGetWGConfig
func ProxyGetWGConfig(timeoutMs C.int) *C.char {
	if proxyWGConfig == nil {
		return nil
	}

	select {
	case config := <-proxyWGConfig:
		return C.CString(config)
	case <-proxyCtx.Done():
		return nil
	case <-time.After(time.Duration(timeoutMs) * time.Millisecond):
		return nil
	}
}

//export ProxyGetStats
func ProxyGetStats(outActive *C.int, outBytesUp *C.long, outBytesDown *C.long) {
	if proxyStats == nil {
		return
	}
	*outActive = C.int(atomic.LoadInt32(&proxyStats.ActiveConnections))
	*outBytesUp = C.long(atomic.LoadInt64(&proxyStats.TotalBytesUp))
	*outBytesDown = C.long(atomic.LoadInt64(&proxyStats.TotalBytesDown))
}

type proxyConfig struct {
	vkLink      string
	vkLink2     string
	peerAddr    string
	listenAddr  string
	connections int
	useTCP      bool
	sni         string
	password    string
	deviceID    string
	captchaMode string
}

func runProxy(ctx context.Context, cfg proxyConfig) {
	log.SetOutput(logBridge{})
	log.SetFlags(0)

	proxyLog(0, "[ПРОКСИ] Запуск TURN-прокси...")

	peer, err := net.ResolveUDPAddr("udp", cfg.peerAddr)
	if err != nil {
		proxyLog(1, "[ПРОКСИ] Ошибка разбора пира: %v", err)
		return
	}

	hashes := ParseHashes(cfg.vkLink)
	if len(hashes) == 0 {
		proxyLog(1, "[ПРОКСИ] Нет хешей VK")
		return
	}

	if cfg.captchaMode != "" {
		captchaMode.Store(cfg.captchaMode)
	} else {
		captchaMode.Store("wv")
	}
	SetUserAgent("Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Mobile/15E148")

	tp := &TurnParams{
		Host:          "",
		Port:          "",
		Hashes:        hashes,
		SecondaryHash: strings.TrimSpace(cfg.vkLink2),
		Sni:           cfg.sni,
	}

	localConn, err := net.ListenPacket("udp", cfg.listenAddr)
	if err != nil {
		proxyLog(1, "[ПРОКСИ] Ошибка слушателя %s: %v", cfg.listenAddr, err)
		return
	}
	context.AfterFunc(ctx, func() { _ = localConn.Close() })

	_, localPort, _ := net.SplitHostPort(cfg.listenAddr)
	if localPort == "" {
		localPort = "9000"
	}

	numWorkers := cfg.connections
	if numWorkers <= 0 {
		numWorkers = 12
	}
	if numWorkers > 72 {
		numWorkers = 72
	}
	numWorkers = (numWorkers / workersPerGroup) * workersPerGroup
	if numWorkers < workersPerGroup {
		numWorkers = workersPerGroup
	}
	numGroups := numWorkers / workersPerGroup
	useUDP := !cfg.useTCP

	proxyLog(0, "[ПРОКСИ] Воркеров: %d (групп: %d) | Слушаю: %s | Пир: %s",
		numWorkers, numGroups, cfg.listenAddr, cfg.peerAddr)

	stats := NewStats()
	proxyStats = stats
	shutdownCh := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(shutdownCh)
	}()
	go stats.RunLoop(shutdownCh)

	disp := NewDispatcher(ctx, localConn, stats)
	defer disp.Shutdown()

	readyOnce := sync.Once{}
	signalReady := func() {
		readyOnce.Do(func() {
			close(proxyReady)
			proxyLog(0, "[ПРОКСИ] DTLS туннель готов ✓")
		})
	}

	// Канал для получения WG конфига от сервера
	configCh := make(chan string, 1)
	proxyWGConfig = make(chan string, 1)
	go func() {
		select {
		case conf := <-configCh:
			if conf != "" {
				// Добавляем MTU если нет
				if !strings.Contains(conf, "MTU =") {
					conf = strings.Replace(conf, "[Interface]", "[Interface]\nMTU = 1280", 1)
				}
				proxyWGConfig <- conf
				proxyLog(0, "[ПРОКСИ] WG конфиг получен от сервера ✓")
			}
		case <-ctx.Done():
		}
	}()

	var wg sync.WaitGroup
	workerIDCounter := 1
	var prevWaitReady <-chan struct{}
	var pauseFlag int32

	for g := 0; g < numGroups; g++ {
		var myWaitReady <-chan struct{}
		var mySignalReady chan<- struct{}

		if g > 0 {
			myWaitReady = prevWaitReady
		}

		ch := make(chan struct{})
		mySignalReady = ch
		prevWaitReady = ch

		if g == 0 {
			origSignal := mySignalReady
			readyCh := make(chan struct{})
			mySignalReady = readyCh
			go func() {
				<-readyCh
				signalReady()
				if origSignal != nil {
					close(origSignal)
				}
			}()
		}

		ids := make([]int, workersPerGroup)
		for i := range ids {
			ids[i] = workerIDCounter
			workerIDCounter++
		}

		cycle := time.Duration(defaultCycleSecs) * time.Second

		isFirst := (g == 0)
		var cc chan<- string
		if isFirst && cfg.password != "" {
			cc = configCh
		}

		wg.Add(1)
		go func(groupID, hashIdx int, workerIds []int, waitR <-chan struct{}, sigR chan<- struct{}, getConf bool, confCh chan<- string) {
			defer wg.Done()
			WorkerGroup(ctx, groupID, hashIdx, tp, peer, disp, localPort, useUDP,
				getConf, confCh, workerIds, cycle, &pauseFlag, cfg.deviceID, cfg.password, stats, waitR, sigR)
		}(g+1, g, ids, myWaitReady, mySignalReady, isFirst, cc)
	}

	wg.Wait()
	proxyLog(0, "[ПРОКСИ] Все воркеры завершены")
}
