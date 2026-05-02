/**
 * trusttunnel_proxy_jni.cpp
 *
 * C-обёртка над реальным TrustTunnel VPN API (vpn.h).
 * Компилируется в libtrustunnel_proxy.so и загружается через ReMandre.
 *
 * Экспортирует три функции для Python/ctypes:
 *   int  StartTTProxy(const char* config_json, int socks5_port)
 *   int  StopTTProxy()
 *   int  GetTTStatus()   → 0=STOPPED 1=CONNECTING 2=CONNECTED -1=ERROR
 *
 * Добавь в CMakeLists.txt платформы:
 *   add_library(trusttunnel_proxy SHARED trusttunnel_proxy_jni.cpp)
 *   target_link_libraries(trusttunnel_proxy vpnlibs_core android log)
 */

#include <atomic>
#include <cstring>
#include <mutex>
#include <string>
#include <thread>

// ── Реальный TrustTunnel API (корень TrustTunnelClient) ──────────────────────
#include "vpn.h"           // ag::Vpn*, vpn_open/connect/listen/stop/close
#include "vpn/platform.h"  // VpnLocation, VpnEndpoint, VpnUpstreamProtocol ...
#include "vpn/utils.h"     // vpn_create_socks_listener, VpnSocksListenerConfig
// ─────────────────────────────────────────────────────────────────────────────

#include <android/log.h>
#define LOG_TAG "TrustTunnelProxy"
#define LOGD(fmt, ...) __android_log_print(ANDROID_LOG_DEBUG,  LOG_TAG, fmt, ##__VA_ARGS__)
#define LOGE(fmt, ...) __android_log_print(ANDROID_LOG_ERROR,  LOG_TAG, fmt, ##__VA_ARGS__)

// ─── Статус (совпадает с кодами в Python плагине) ────────────────────────────
enum class ProxyStatus : int {
    STOPPED    =  0,
    CONNECTING =  1,
    CONNECTED  =  2,
    ERROR      = -1,
};

// ─── Глобальный стейт ────────────────────────────────────────────────────────
static std::mutex                g_mutex;
static ag::Vpn                  *g_vpn   = nullptr;
static std::atomic<ProxyStatus>  g_status { ProxyStatus::STOPPED };

// ─── Утилита: достать строку из JSON без зависимостей ────────────────────────
// Python плагин присылает плоский JSON:
// { "endpoint.address":"host:port", "auth.username":"u", "auth.password":"p",
//   "interface.dns":"8.8.8.8", "upstream.protocol":"http2" }
static std::string json_get(const std::string &json, const char *key) {
    std::string needle = std::string("\"") + key + "\"";
    auto pos = json.find(needle);
    if (pos == std::string::npos) return {};
    pos = json.find(':', pos + needle.size());
    if (pos == std::string::npos) return {};
    pos = json.find('"', pos + 1);
    if (pos == std::string::npos) return {};
    auto end = json.find('"', pos + 1);
    if (end == std::string::npos) return {};
    return json.substr(pos + 1, end - pos - 1);
}

// ─── VPN event handler ───────────────────────────────────────────────────────
static void vpn_event_handler(void * /*arg*/, ag::VpnEvent what, void *data) {
    switch (what) {

    case ag::VPN_EVENT_STATE_CHANGED: {
        auto *ev = static_cast<ag::VpnStateChangedEvent *>(data);
        switch (ev->state) {
        case ag::VPN_SS_CONNECTED:
            LOGD("state → CONNECTED");
            g_status.store(ProxyStatus::CONNECTED);
            break;
        case ag::VPN_SS_CONNECTING:
        case ag::VPN_SS_RECOVERING:
        case ag::VPN_SS_WAITING_RECOVERY:
            LOGD("state → CONNECTING/RECOVERING");
            g_status.store(ProxyStatus::CONNECTING);
            break;
        case ag::VPN_SS_DISCONNECTED:
        case ag::VPN_SS_WAITING_FOR_NETWORK:
            LOGD("state → DISCONNECTED");
            // Если мы сами не вызывали StopTTProxy — считаем ошибкой
            if (g_status.load() == ProxyStatus::CONNECTING ||
                g_status.load() == ProxyStatus::CONNECTED) {
                g_status.store(ProxyStatus::ERROR);
            }
            break;
        }
        break;
    }

    case ag::VPN_EVENT_CONNECT_REQUEST:
        // Для SOCKS5-режима нужно подтвердить каждый входящий коннект
        if (g_vpn && data) {
            auto *ev = static_cast<ag::VpnConnectRequestEvent *>(data);
            ag::VpnConnectionInfo info{};
            info.id      = ev->id;
            info.action  = ag::VPN_CA_DEFAULT; // маршрутизируем по правилам VPN
            info.appname = "";
            info.uid     = -1;
            ag::vpn_complete_connect_request(g_vpn, &info);
        }
        break;

    case ag::VPN_EVENT_PROTECT_SOCKET:
        // В режиме SOCKS5 без TUN защищать сокеты не нужно
        break;

    default:
        break;
    }
}

// ─── Внутренняя остановка (вызывается под локом) ─────────────────────────────
static void stop_locked() {
    if (g_vpn) {
        ag::vpn_stop(g_vpn);
        ag::vpn_close(g_vpn);
        g_vpn = nullptr;
        LOGD("VPN stopped and closed");
    }
    g_status.store(ProxyStatus::STOPPED);
}

// =============================================================================
// Публичный C-интерфейс — вызывается из Python через ctypes
// =============================================================================
extern "C" {

/**
 * StartTTProxy
 *
 * @param config_json  Плоский JSON от Python плагина (TTConfigHelper.to_json):
 *                     {
 *                       "endpoint.address":   "vpn.example.com:443",
 *                       "auth.username":      "myuser",
 *                       "auth.password":      "mypass",
 *                       "interface.dns":      "8.8.8.8",
 *                       "upstream.protocol":  "http2"      // auto / http2 / http3
 *                     }
 * @param socks5_port  Порт локального SOCKS5 (например 2338)
 * @return 0 = успех, отрицательное = код ошибки
 */
__attribute__((visibility("default")))
int StartTTProxy(const char *config_json, int socks5_port) {
    if (!config_json || socks5_port <= 0) {
        LOGE("StartTTProxy: bad args");
        return -1;
    }

    std::lock_guard<std::mutex> lock(g_mutex);

    // Рестарт если уже запущен
    if (g_vpn) {
        LOGD("StartTTProxy: restarting");
        stop_locked();
    }

    std::string json(config_json);
    LOGD("StartTTProxy port=%d json_len=%zu", socks5_port, json.size());

    // ── Разбираем JSON ────────────────────────────────────────────────────
    std::string address  = json_get(json, "endpoint.address");
    std::string username = json_get(json, "auth.username");
    std::string password = json_get(json, "auth.password");
    std::string dns      = json_get(json, "interface.dns");
    std::string proto_s  = json_get(json, "upstream.protocol");

    if (address.empty()) {
        LOGE("StartTTProxy: endpoint.address missing");
        return -2;
    }

    // host:port → host + port
    std::string host;
    uint16_t port = 443;
    {
        auto colon = address.rfind(':');
        if (colon != std::string::npos) {
            host = address.substr(0, colon);
            try { port = static_cast<uint16_t>(std::stoi(address.substr(colon + 1))); }
            catch (...) { port = 443; }
        } else {
            host = address;
        }
    }

    // ── VpnSettings ───────────────────────────────────────────────────────
    ag::VpnSettings settings{};
    settings.handler.func              = vpn_event_handler;
    settings.handler.arg               = nullptr;
    settings.mode                      = ag::VPN_MODE_GENERAL;
    settings.exclusions                = {};      // пусто — весь трафик в туннель
    settings.killswitch_enabled        = false;   // не блокируем трафик при отрыве
    settings.tmp_files_base_path       = nullptr;
    settings.conn_memory_buffer_threshold = 0;
    settings.max_conn_buffer_file_size    = 0;
    settings.ssl_sessions_storage_path   = nullptr;

    g_vpn = ag::vpn_open(&settings);
    if (!g_vpn) {
        LOGE("StartTTProxy: vpn_open failed");
        g_status.store(ProxyStatus::ERROR);
        return -3;
    }

    // ── Протокол ──────────────────────────────────────────────────────────
    ag::VpnUpstreamProtocol main_proto = ag::VPN_UP_AUTO;
    if      (proto_s == "http2") main_proto = ag::VPN_UP_HTTP2;
    else if (proto_s == "http3") main_proto = ag::VPN_UP_HTTP3;

    // ── VpnEndpoint + VpnLocation ─────────────────────────────────────────
    // ag::VpnStr — { const char* data; size_t size } — lightweight string view
    ag::VpnEndpoint endpoint{};
    endpoint.address = ag::VpnStr{ host.c_str(), host.size() };
    endpoint.port    = port;

    ag::VpnLocation location{};
    location.endpoints = ag::AG_ARRAY_OF(ag::VpnEndpoint){ &endpoint, 1 };
    location.id        = ag::VpnStr{ "default", 7 };

    // ── VpnConnectParameters ──────────────────────────────────────────────
    ag::VpnConnectParameters params{};
    auto &up = params.upstream_config;
    up.main_protocol             = main_proto;
    up.location                  = location;
    up.timeout_ms                = 0; // VPN_DEFAULT_ENDPOINT_UPSTREAM_TIMEOUT_MS
    up.health_check_timeout_ms   = 0; // VPN_DEFAULT_HEALTH_CHECK_TIMEOUT_MS
    up.anti_dpi                  = true; // обфускация — главная фича TrustTunnel
    up.recovery.backoff_rate         = 0.0f; // VPN_DEFAULT_RECOVERY_BACKOFF_RATE
    up.recovery.location_update_period_ms = 0;

    if (!username.empty()) {
        up.username = username.c_str();
        up.password = password.c_str();
    }

    params.retry_info.policy      = ag::VPN_CRP_FALL_INTO_RECOVERY;
    params.retry_info.attempts_num = 5; // VPN_DEFAULT_CONNECT_ATTEMPTS_NUM

    g_status.store(ProxyStatus::CONNECTING);

    // ── vpn_connect ───────────────────────────────────────────────────────
    ag::VpnError err = ag::vpn_connect(g_vpn, &params);
    if (err.code != ag::VPN_EC_NOERROR) {
        LOGE("StartTTProxy: vpn_connect error code=%d", static_cast<int>(err.code));
        stop_locked();
        return -4;
    }

    // ── SOCKS5 listener на 127.0.0.1:socks5_port ─────────────────────────
    std::string socks_addr_str = "127.0.0.1:" + std::to_string(socks5_port);

    ag::VpnSocksListenerConfig socks_cfg{};
    // SocketAddressStorage::from_string — API из common/socket_address.h
    socks_cfg.listen_address = ag::SocketAddressStorage::from_string(socks_addr_str);
    socks_cfg.username = nullptr; // локальный SOCKS5 — без авторизации
    socks_cfg.password = nullptr;

    ag::VpnListener *listener = ag::vpn_create_socks_listener(g_vpn, &socks_cfg);
    if (!listener) {
        LOGE("StartTTProxy: vpn_create_socks_listener failed");
        stop_locked();
        return -5;
    }

    // ── DNS upstream ──────────────────────────────────────────────────────
    std::string dns_str = dns.empty() ? "8.8.8.8" : dns;
    const char *dns_arr[] = { dns_str.c_str() };

    ag::VpnListenerConfig listener_cfg{};
    listener_cfg.timeout_ms    = 0; // VPN_DEFAULT_TCP_TIMEOUT_MS
    listener_cfg.dns_upstreams = ag::AG_ARRAY_OF(const char *){ dns_arr, 1 };

    ag::VpnError listen_err = ag::vpn_listen(g_vpn, listener, &listener_cfg);
    if (listen_err.code != ag::VPN_EC_NOERROR) {
        LOGE("StartTTProxy: vpn_listen error code=%d", static_cast<int>(listen_err.code));
        stop_locked();
        return -6;
    }

    // Лог реального порта (полезно если передали 0)
    ag::SocketAddressStorage actual_addr = ag::vpn_get_socks_listener_address(g_vpn);
    LOGD("StartTTProxy: SOCKS5 up on %s", actual_addr.to_string().c_str());

    // Статус CONNECTED выставит event handler когда придёт VPN_SS_CONNECTED.
    // На случай если event не придёт быстро — оставляем CONNECTING, Python
    // плагин игнорирует это и сразу выставляет прокси в Telegram.
    return 0;
}

/**
 * StopTTProxy — остановить VPN и SOCKS5 listener.
 * @return 0
 */
__attribute__((visibility("default")))
int StopTTProxy() {
    std::lock_guard<std::mutex> lock(g_mutex);
    stop_locked();
    return 0;
}

/**
 * GetTTStatus — текущий статус соединения.
 * @return 0=STOPPED  1=CONNECTING  2=CONNECTED  -1=ERROR
 */
__attribute__((visibility("default")))
int GetTTStatus() {
    return static_cast<int>(g_status.load());
}

} // extern "C"
