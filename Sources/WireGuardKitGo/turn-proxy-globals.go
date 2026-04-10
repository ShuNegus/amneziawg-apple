package main

import "sync/atomic"

var (
	vkAppID     atomic.Value // string
	vkAppSecret atomic.Value // string
	captchaMode atomic.Value // string — "rjs" или "wv"
)

// CaptchaResultCh — канал для получения токена капчи из внешнего решателя (WebView)
var CaptchaResultCh = make(chan string, 1)

func drainCaptchaResult() {
	select {
	case <-CaptchaResultCh:
	default:
	}
}

func init() {
	vkAppID.Store("6287487")
	vkAppSecret.Store("QbYic1K3lEV5kTGiqlq2")
	captchaMode.Store("wv")
}
