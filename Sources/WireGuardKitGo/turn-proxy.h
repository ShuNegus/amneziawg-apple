#ifndef TURN_PROXY_H
#define TURN_PROXY_H

#include <stdint.h>

typedef void (*proxy_logger_fn)(void *context, int level, const char *msg);
typedef void (*proxy_captcha_fn)(void *context, const char *url, const char *session_token);

typedef struct {
    const char *vkLink;
    const char *vkLink2;
    const char *peerAddr;
    const char *listenAddr;
    int         connections;
    int         useTCP;
    const char *sni;
    const char *password;
    const char *deviceID;
    const char *captchaMode;
} ProxyConfig;

/* Exported functions declared in CGO-generated header */

#endif /* TURN_PROXY_H */
