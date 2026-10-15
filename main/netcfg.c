#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "esp_log.h"
#include "nvs.h"
#include "lwip/sockets.h"
#include "netcfg.h"

static const char *TAG = "NETCFG";
#define NVS_NS_NET "netcfg"

/* Predefiniti = comportamento storico del firmware (ICS di Windows: 192.168.137.0/24). */
#define DEF_ETH_STATIC  1
#define DEF_ETH_IP      "192.168.137.200"
#define DEF_ETH_MASK    "255.255.255.0"
#define DEF_ETH_GW      "192.168.137.1"
#define DEF_ETH_DNS     "192.168.137.1"
#define DEF_AP_SSID     "LoggerWIFI"
#define DEF_AP_CHANNEL  6
#define DEF_AP_DBM      8
/* Subnet dell'AP (default esp_netif): la rete Ethernet non deve sovrapporsi, o il NAT si rompe. */
#define AP_NET   0xC0A80400u   /* 192.168.4.0 */
#define AP_MASK  0xFFFFFF00u

static eth_cfg_t s_eth;
static ap_cfg_t  s_ap;

/* ---------- utilita' IPv4 (host order) ---------- */
static bool parse_ip4(const char *s, uint32_t *out)
{
    unsigned a, b, c, d; int n = 0;
    if (!s || sscanf(s, " %3u.%3u.%3u.%3u %n", &a, &b, &c, &d, &n) != 4 || s[n]) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    *out = (a << 24) | (b << 16) | (c << 8) | d;
    return true;
}

static void fmt_ip4(uint32_t v, char *o /* >=16 */)
{
    snprintf(o, 16, "%u.%u.%u.%u", (unsigned)(v >> 24), (unsigned)((v >> 16) & 255),
             (unsigned)((v >> 8) & 255), (unsigned)(v & 255));
}

static void eth_defaults(eth_cfg_t *c)
{
    memset(c, 0, sizeof *c);
    c->use_static = DEF_ETH_STATIC;
    strcpy(c->ip, DEF_ETH_IP); strcpy(c->mask, DEF_ETH_MASK);
    strcpy(c->gw, DEF_ETH_GW); strcpy(c->dns, DEF_ETH_DNS);
}

static void ap_defaults(ap_cfg_t *c)
{
    memset(c, 0, sizeof *c);
    strcpy(c->ssid, DEF_AP_SSID);
    c->channel = DEF_AP_CHANNEL;
    c->tx_dbm = DEF_AP_DBM;
}

#define ERR(...) do { if (err && err_len) snprintf(err, err_len, __VA_ARGS__); } while (0)

/* Controlla e normalizza (es. DNS vuoto = gateway). In DHCP i campi fissi non contano. */
static bool eth_validate(eth_cfg_t *c, char *err, size_t err_len)
{
    c->use_static = c->use_static ? 1 : 0;
    if (!c->use_static) return true;
    uint32_t ip, mask, gw, dns;
    if (!parse_ip4(c->ip, &ip))     { ERR("Indirizzo IP non valido: \"%s\"", c->ip); return false; }
    if (!parse_ip4(c->mask, &mask)) { ERR("Maschera non valida: \"%s\"", c->mask); return false; }
    uint32_t inv = ~mask;
    if (mask == 0 || (inv & (inv + 1)) != 0 || mask > 0xFFFFFFFCu) {
        ERR("Maschera non valida (serve una maschera contigua, al massimo /30, es. 255.255.255.0)");
        return false;
    }
    if (!parse_ip4(c->gw, &gw))     { ERR("Gateway non valido: \"%s\"", c->gw); return false; }
    if (c->dns[0]) { if (!parse_ip4(c->dns, &dns)) { ERR("DNS non valido: \"%s\"", c->dns); return false; } }
    else dns = gw;
    uint8_t first = (uint8_t)(ip >> 24);
    if (ip == 0 || first == 127 || first >= 224) { ERR("Indirizzo IP non utilizzabile"); return false; }
    if ((ip & inv) == 0 || (ip & inv) == inv) { ERR("L'IP non puo' essere l'indirizzo di rete o di broadcast"); return false; }
    if ((gw & mask) != (ip & mask)) { ERR("Il gateway deve stare nella stessa rete dell'IP"); return false; }
    if (gw == ip) { ERR("Il gateway non puo' coincidere con l'IP del dispositivo"); return false; }
    uint32_t cm = mask & AP_MASK;
    if ((ip & cm) == (AP_NET & cm)) {
        ERR("La rete %s/%s si sovrappone a quella dell'access point (192.168.4.0/24): scegli un'altra rete", c->ip, c->mask);
        return false;
    }
    fmt_ip4(ip, c->ip); fmt_ip4(mask, c->mask); fmt_ip4(gw, c->gw); fmt_ip4(dns, c->dns);
    return true;
}

static bool ap_validate(ap_cfg_t *c, char *err, size_t err_len)
{
    c->ssid[sizeof c->ssid - 1] = 0;
    size_t l = strlen(c->ssid);
    if (l < 1 || l > 31) { ERR("SSID: da 1 a 31 caratteri"); return false; }
    if (c->channel < 1 || c->channel > 13) { ERR("Canale Wi-Fi: 1..13"); return false; }
    if (c->tx_dbm < 2 || c->tx_dbm > 20) { ERR("Potenza Wi-Fi: 2..20 dBm"); return false; }
    c->hidden = c->hidden ? 1 : 0;
    return true;
}

/* ---------- NVS ---------- */
static esp_err_t get_str(nvs_handle_t h, const char *k, char *dst, size_t sz)
{
    size_t len = sz;
    esp_err_t e = nvs_get_str(h, k, dst, &len);
    if (e != ESP_OK) dst[0] = 0;
    return e;
}

bool netcfg_eth_read_nvs(eth_cfg_t *out)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS_NET, NVS_READONLY, &h) != ESP_OK) return false;
    uint8_t m = 0;
    bool ok = nvs_get_u8(h, "eth_mode", &m) == ESP_OK;
    if (ok) {
        eth_cfg_t c; memset(&c, 0, sizeof c);
        c.use_static = m ? 1 : 0;
        get_str(h, "eth_ip", c.ip, sizeof c.ip);
        get_str(h, "eth_mask", c.mask, sizeof c.mask);
        get_str(h, "eth_gw", c.gw, sizeof c.gw);
        get_str(h, "eth_dns", c.dns, sizeof c.dns);
        *out = c;
    }
    nvs_close(h);
    return ok;
}

bool netcfg_ap_read_nvs(ap_cfg_t *out)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS_NET, NVS_READONLY, &h) != ESP_OK) return false;
    ap_cfg_t c; memset(&c, 0, sizeof c);
    bool ok = get_str(h, "ap_ssid", c.ssid, sizeof c.ssid) == ESP_OK;
    ok = ok && nvs_get_u8(h, "ap_ch", &c.channel) == ESP_OK;
    ok = ok && nvs_get_u8(h, "ap_dbm", &c.tx_dbm) == ESP_OK;
    if (nvs_get_u8(h, "ap_hid", &c.hidden) != ESP_OK) c.hidden = 0;
    nvs_close(h);
    if (ok) *out = c;
    return ok;
}

static esp_err_t eth_write(const eth_cfg_t *c)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(NVS_NS_NET, NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    e = nvs_set_u8(h, "eth_mode", c->use_static);
    if (e == ESP_OK) e = nvs_set_str(h, "eth_ip", c->ip);
    if (e == ESP_OK) e = nvs_set_str(h, "eth_mask", c->mask);
    if (e == ESP_OK) e = nvs_set_str(h, "eth_gw", c->gw);
    if (e == ESP_OK) e = nvs_set_str(h, "eth_dns", c->dns);
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

static esp_err_t ap_write(const ap_cfg_t *c)
{
    nvs_handle_t h;
    esp_err_t e = nvs_open(NVS_NS_NET, NVS_READWRITE, &h);
    if (e != ESP_OK) return e;
    e = nvs_set_str(h, "ap_ssid", c->ssid);
    if (e == ESP_OK) e = nvs_set_u8(h, "ap_ch", c->channel);
    if (e == ESP_OK) e = nvs_set_u8(h, "ap_dbm", c->tx_dbm);
    if (e == ESP_OK) e = nvs_set_u8(h, "ap_hid", c->hidden);
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    return e;
}

void netcfg_load(void)
{
    eth_defaults(&s_eth);
    ap_defaults(&s_ap);

    eth_cfg_t e;
    if (netcfg_eth_read_nvs(&e)) {
        char msg[120];
        if (eth_validate(&e, msg, sizeof msg)) {
            s_eth = e;
            ESP_LOGI(TAG, "[ETH] da NVS: %s", e.use_static ? "IP fisso" : "DHCP");
        } else {
            ESP_LOGW(TAG, "[ETH] configurazione in NVS non valida (%s): uso i predefiniti", msg);
        }
    } else {
        ESP_LOGI(TAG, "[ETH] nessuna configurazione in NVS: predefiniti (IP fisso %s)", s_eth.ip);
    }

    ap_cfg_t a;
    if (netcfg_ap_read_nvs(&a)) {
        char msg[80];
        if (ap_validate(&a, msg, sizeof msg)) {
            s_ap = a;
            ESP_LOGI(TAG, "[AP] da NVS: \"%s\" ch %u %u dBm%s", a.ssid, a.channel, a.tx_dbm, a.hidden ? " nascosto" : "");
        } else {
            ESP_LOGW(TAG, "[AP] configurazione in NVS non valida (%s): uso i predefiniti", msg);
        }
    } else {
        ESP_LOGI(TAG, "[AP] nessuna configurazione in NVS: predefiniti (\"%s\" ch %u)", s_ap.ssid, s_ap.channel);
    }
}

void netcfg_eth_get(eth_cfg_t *out) { *out = s_eth; }
void netcfg_ap_get(ap_cfg_t *out)   { *out = s_ap; }

bool netcfg_eth_set(const eth_cfg_t *in, char *err, size_t err_len)
{
    eth_cfg_t c = *in;
    if (!eth_validate(&c, err, err_len)) return false;
    esp_err_t e = eth_write(&c);
    if (e != ESP_OK) { ERR("Scrittura NVS fallita (%s)", esp_err_to_name(e)); return false; }
    eth_cfg_t back;
    if (!netcfg_eth_read_nvs(&back) || back.use_static != c.use_static || strcmp(back.ip, c.ip) ||
        strcmp(back.mask, c.mask) || strcmp(back.gw, c.gw) || strcmp(back.dns, c.dns)) {
        ERR("Verifica NVS fallita: il valore riletto non coincide con quello scritto");
        return false;
    }
    s_eth = c;
    ESP_LOGI(TAG, "[ETH] salvato in NVS (verificato): %s ip=%s mask=%s gw=%s dns=%s",
             c.use_static ? "IP fisso" : "DHCP", c.ip, c.mask, c.gw, c.dns);
    return true;
}

bool netcfg_ap_set(const ap_cfg_t *in, char *err, size_t err_len)
{
    ap_cfg_t c = *in;
    if (!ap_validate(&c, err, err_len)) return false;
    esp_err_t e = ap_write(&c);
    if (e != ESP_OK) { ERR("Scrittura NVS fallita (%s)", esp_err_to_name(e)); return false; }
    ap_cfg_t back;
    if (!netcfg_ap_read_nvs(&back) || strcmp(back.ssid, c.ssid) || back.channel != c.channel ||
        back.tx_dbm != c.tx_dbm || back.hidden != c.hidden) {
        ERR("Verifica NVS fallita: il valore riletto non coincide con quello scritto");
        return false;
    }
    s_ap = c;
    ESP_LOGI(TAG, "[AP] salvato in NVS (verificato): \"%s\" ch %u %u dBm%s", c.ssid, c.channel, c.tx_dbm,
             c.hidden ? " nascosto" : "");
    return true;
}

bool netcfg_erase(void)
{
    nvs_handle_t h;
    if (nvs_open(NVS_NS_NET, NVS_READWRITE, &h) != ESP_OK) return false;
    esp_err_t e = nvs_erase_all(h);
    if (e == ESP_OK) e = nvs_commit(h);
    nvs_close(h);
    ESP_LOGW(TAG, "configurazione di rete cancellata da NVS -> %s", esp_err_to_name(e));
    return e == ESP_OK;
}

esp_err_t netcfg_eth_apply(esp_netif_t *n, bool hot)
{
    if (!n) return ESP_ERR_INVALID_ARG;
    eth_cfg_t c; netcfg_eth_get(&c);

    if (!c.use_static && !hot) {
        ESP_LOGI(TAG, "[ETH] DHCP: l'IP arrivera' dal router");
        return ESP_OK;                       /* il client DHCP parte da solo con esp_eth_start */
    }

    esp_err_t r = esp_netif_dhcpc_stop(n);
    if (r != ESP_OK && r != ESP_ERR_ESP_NETIF_DHCP_ALREADY_STOPPED)
        ESP_LOGW(TAG, "[ETH] dhcpc_stop -> %s", esp_err_to_name(r));

    if (c.use_static) {
        uint32_t ip, mask, gw, dns;
        parse_ip4(c.ip, &ip); parse_ip4(c.mask, &mask); parse_ip4(c.gw, &gw);
        if (!parse_ip4(c.dns, &dns)) dns = gw;
        esp_netif_ip_info_t ipi = {0};
        ipi.ip.addr      = htonl(ip);
        ipi.netmask.addr = htonl(mask);
        ipi.gw.addr      = htonl(gw);
        esp_err_t r2 = esp_netif_set_ip_info(n, &ipi);
        esp_netif_dns_info_t di = {0};
        di.ip.type = ESP_IPADDR_TYPE_V4;
        di.ip.u_addr.ip4.addr = htonl(dns);
        esp_err_t r3 = esp_netif_set_dns_info(n, ESP_NETIF_DNS_MAIN, &di);
        ESP_LOGI(TAG, "[ETH] IP fisso %s/%s gw %s dns %s (set_ip=%s set_dns=%s)", c.ip, c.mask, c.gw, c.dns,
                 esp_err_to_name(r2), esp_err_to_name(r3));
        return r2 != ESP_OK ? r2 : r3;
    }

    /* da IP fisso (o altro) a DHCP, a caldo: azzera l'indirizzo e riavvia il client */
    esp_netif_ip_info_t z = {0};
    esp_netif_set_ip_info(n, &z);
    r = esp_netif_dhcpc_start(n);
    ESP_LOGI(TAG, "[ETH] DHCP avviato a caldo (%s)", esp_err_to_name(r));
    return r == ESP_ERR_ESP_NETIF_DHCP_ALREADY_STARTED ? ESP_OK : r;
}
