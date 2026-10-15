#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_http_server.h"
#include "esp_wifi.h"
#include "esp_netif.h"
#include "esp_system.h"
#include "esp_mac.h"
#include "esp_timer.h"
#include "webcfg.h"
#include "filter.h"
#include "capture.h"
#include "netcfg.h"
#include "esp_heap_caps.h"
#include "lwip/netdb.h"
#include "lwip/sockets.h"

static const char *TAG = "WEBCFG";
extern volatile int g_capture_tap_on;
static int s_promisc_on = 0;

/* ---- Diagnostica: probe request visti dalla radio mentre l'AP e' attivo ---- */
#define PR_N 8
static volatile uint32_t s_probe_total = 0;
static volatile uint32_t s_mgmt_total  = 0;
static struct { uint8_t mac[6]; int8_t rssi; uint8_t ch; int64_t t; } s_pr[PR_N];
static volatile int s_pr_idx = 0;

static void promisc_cb(void *buf, wifi_promiscuous_pkt_type_t type)
{
    if (type != WIFI_PKT_MGMT) return;
    const wifi_promiscuous_pkt_t *p = (const wifi_promiscuous_pkt_t *)buf;
    s_mgmt_total++;
    if (p->payload[0] == 0x40) {               /* probe request */
        s_probe_total++;
        int i = s_pr_idx % PR_N; s_pr_idx++;
        memcpy(s_pr[i].mac, p->payload + 10, 6);
        s_pr[i].rssi = p->rx_ctrl.rssi;
        s_pr[i].ch = p->rx_ctrl.channel;
        s_pr[i].t = esp_timer_get_time();
    }
}

static void promisc_enable(void)
{
    wifi_promiscuous_filter_t f = { .filter_mask = WIFI_PROMIS_FILTER_MASK_MGMT };
    esp_wifi_set_promiscuous_filter(&f);
    esp_wifi_set_promiscuous_rx_cb(&promisc_cb);
    esp_err_t e = esp_wifi_set_promiscuous(true);
    ESP_LOGI(TAG, "promiscuous mgmt -> %s", esp_err_to_name(e));
}

/* ---- Pagina ---- */
static esp_err_t root_get(httpd_req_t *req)
{
    wifi_config_t c; esp_wifi_get_config(WIFI_IF_AP, &c);
    uint8_t ch = 0; wifi_second_chan_t sc; esp_wifi_get_channel(&ch, &sc);
    int8_t txp = 0; esp_wifi_get_max_tx_power(&txp);
    wifi_country_t cc; esp_wifi_get_country(&cc);
    wifi_sta_list_t sl = {0}; esp_wifi_ap_get_sta_list(&sl);
    uint8_t m[6]; esp_wifi_get_mac(WIFI_IF_AP, m);

    char *b = malloc(4096);
    if (!b) return httpd_resp_send_500(req);
    int n = snprintf(b, 4096,
      "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
      "<title>Sniffer WiFi</title><body style='font-family:sans-serif;max-width:640px;margin:1em auto'>"
      "<h2>Sniffer WiFi - diagnostica AP</h2>"
      "<p>SSID <b>%s</b> | canale <b>%u</b> | potenza <b>%.1f dBm</b> (%d) | nascosto %d<br>"
      "Paese %.2s ch %u-%u | MAC AP %02x:%02x:%02x:%02x:%02x:%02x<br>"
      "Stazioni connesse: <b>%d</b> | heap libero %lu | uptime %llu s</p>"
      "<p>Frame di gestione ricevuti: <b>%lu</b> | <b>probe request</b> ricevute: <b>%lu</b></p>"
      "<table border=1 cellpadding=4><tr><th>ultimi probe da</th><th>RSSI</th><th>ch</th><th>fa (s)</th></tr>",
      (char *)c.ap.ssid, ch, txp * 0.25, txp, c.ap.ssid_hidden,
      cc.cc, cc.schan, cc.schan + cc.nchan - 1,
      m[0],m[1],m[2],m[3],m[4],m[5],
      sl.num, (unsigned long)esp_get_free_heap_size(), (unsigned long long)(esp_timer_get_time()/1000000),
      (unsigned long)s_mgmt_total, (unsigned long)s_probe_total);
    int cnt = s_pr_idx < PR_N ? s_pr_idx : PR_N;
    for (int i = 0; i < cnt && n < 3300; i++) {
        n += snprintf(b + n, 4096 - n, "<tr><td>%02x:%02x:%02x:%02x:%02x:%02x</td><td>%d</td><td>%u</td><td>%lld</td></tr>",
            s_pr[i].mac[0],s_pr[i].mac[1],s_pr[i].mac[2],s_pr[i].mac[3],s_pr[i].mac[4],s_pr[i].mac[5],
            s_pr[i].rssi, s_pr[i].ch, (long long)((esp_timer_get_time()-s_pr[i].t)/1000000));
    }
    n += snprintf(b + n, 4096 - n,
      "</table><p><i>Se i probe aumentano quando cerchi reti col telefono, l'ESP riceve ma forse non trasmette i beacon.</i></p>"
      "<h3>Modifica al volo</h3><form action=/set>"
      "SSID <input name=ssid value='%s'><br>"
      "Canale (1-13) <input name=ch value=%u size=3><br>"
      "Potenza dBm (2-20) <input name=pw value=%d size=3><br>"
      "Nascosto <input type=checkbox name=hid value=1><br>"
      "<input type=submit value=Applica> <a href=/>aggiorna</a> <small>(applicato subito e salvato in NVS: resta dopo il riavvio)</small></form>"
      "<p><a href=/net><b>Rete Ethernet: DHCP / IP fisso</b></a> (verso router o PC con condivisione)</p>"
      "<p><a href=/wireshark><b>Cattura su Wireshark</b></a> (comando da lanciare sul PC per lo stream USB)</p>"
      "<p><a href=/filter><b>Filtro di cattura (regole testuali)</b></a> - %d regole, filtro %s <a href='/toggle?filter=1'>on</a> <a href='/toggle?filter=0'>off</a></p>"
      "<p>Tap cattura: %d <a href='/toggle?tap=0'>spegni</a> <a href='/toggle?tap=1'>accendi</a> | Promiscuous: %d <a href='/toggle?promisc=1'>on</a> <a href='/toggle?promisc=0'>off</a></p>"
      "<p><a href=/nettest>test rete ESP (DNS + TCP verso internet)</a> | <a href=/restart>riavvia ESP</a></p>", (char *)c.ap.ssid, ch, txp / 4, filter_rule_count(), filter_is_enabled() ? "attivo" : "SPENTO", g_capture_tap_on, s_promisc_on);
    if (n > 4095) n = 4095;      /* snprintf restituisce la lunghezza "voluta": non leggere oltre il buffer */
    httpd_resp_set_type(req, "text/html");
    httpd_resp_send(req, b, n);
    free(b);
    return ESP_OK;
}

static void urldecode(char *s)
{
    char *o = s;
    for (; *s; s++) {
        if (*s == '+') *o++ = ' ';
        else if (*s == '%' && s[1] && s[2]) { char h[3] = { s[1], s[2], 0 }; *o++ = (char)strtol(h, NULL, 16); s += 2; }
        else *o++ = *s;
    }
    *o = 0;
}

static esp_err_t set_get(httpd_req_t *req)
{
    char q[200], v[40];
    if (httpd_req_get_url_query_str(req, q, sizeof q) != ESP_OK) q[0] = 0;
    wifi_config_t c; esp_wifi_get_config(WIFI_IF_AP, &c);
    if (httpd_query_key_value(q, "ssid", v, sizeof v) == ESP_OK) {
        urldecode(v);
        if (v[0] && strlen(v) < 32) { strcpy((char *)c.ap.ssid, v); c.ap.ssid_len = strlen(v); }
    }
    if (httpd_query_key_value(q, "ch", v, sizeof v) == ESP_OK) {
        int ch = atoi(v); if (ch >= 1 && ch <= 13) c.ap.channel = ch;
    }
    c.ap.ssid_hidden = (httpd_query_key_value(q, "hid", v, sizeof v) == ESP_OK) ? 1 : 0;
    c.ap.authmode = WIFI_AUTH_OPEN;
    esp_err_t e1 = esp_wifi_set_config(WIFI_IF_AP, &c);
    esp_err_t e2 = ESP_OK;
    if (httpd_query_key_value(q, "pw", v, sizeof v) == ESP_OK) {
        int pw = atoi(v); if (pw >= 2 && pw <= 20) e2 = esp_wifi_set_max_tx_power(pw * 4);
    }
    ESP_LOGI(TAG, "set_config=%s tx_power=%s", esp_err_to_name(e1), esp_err_to_name(e2));
    if (e1 == ESP_OK) {                         /* salva in NVS: l'AP riparte cosi' dopo il riavvio */
        ap_cfg_t ac; netcfg_ap_get(&ac);
        strncpy(ac.ssid, (char *)c.ap.ssid, sizeof ac.ssid - 1); ac.ssid[sizeof ac.ssid - 1] = 0;
        ac.channel = c.ap.channel;
        ac.hidden = c.ap.ssid_hidden;
        int8_t tp = 0;
        if (esp_wifi_get_max_tx_power(&tp) == ESP_OK && tp / 4 >= 2 && tp / 4 <= 20) ac.tx_dbm = (uint8_t)(tp / 4);
        char er[96] = "";
        if (!netcfg_ap_set(&ac, er, sizeof er)) ESP_LOGE(TAG, "salvataggio AP in NVS: %s", er);
    }
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t toggle_get(httpd_req_t *req)
{
    char q[64], v[8];
    if (httpd_req_get_url_query_str(req, q, sizeof q) != ESP_OK) q[0] = 0;
    if (httpd_query_key_value(q, "tap", v, sizeof v) == ESP_OK) g_capture_tap_on = atoi(v);
    if (httpd_query_key_value(q, "filter", v, sizeof v) == ESP_OK) filter_set_enabled(atoi(v) != 0);
    if (httpd_query_key_value(q, "promisc", v, sizeof v) == ESP_OK) {
        int on = atoi(v);
        if (on && !s_promisc_on) promisc_enable();
        if (!on && s_promisc_on) esp_wifi_set_promiscuous(false);
        s_promisc_on = on;
    }
    httpd_resp_set_status(req, "303 See Other");
    httpd_resp_set_hdr(req, "Location", "/");
    httpd_resp_send(req, NULL, 0);
    return ESP_OK;
}

static esp_err_t nettest_get(httpd_req_t *req)
{
    char out[900]; int n = 0;
    esp_netif_t *eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_t *def = esp_netif_get_default_netif();
    esp_netif_ip_info_t ip = {0}; esp_netif_dns_info_t d = {0};
    if (eth) { esp_netif_get_ip_info(eth, &ip); esp_netif_get_dns_info(eth, ESP_NETIF_DNS_MAIN, &d); }
    n += snprintf(out + n, sizeof out - n, "ETH ip=" IPSTR " gw=" IPSTR " dns=" IPSTR " default_netif=%s\n",
                  IP2STR(&ip.ip), IP2STR(&ip.gw), IP2STR(&d.ip.u_addr.ip4),
                  def ? esp_netif_get_ifkey(def) : "NULL");
    struct addrinfo hints = { .ai_family = AF_INET, .ai_socktype = SOCK_STREAM }, *res = NULL;
    int r = getaddrinfo("example.com", "80", &hints, &res);
    if (r == 0 && res) {
        struct sockaddr_in *sa = (struct sockaddr_in *)res->ai_addr;
        n += snprintf(out + n, sizeof out - n, "DNS example.com -> %s : OK\n", inet_ntoa(sa->sin_addr));
        freeaddrinfo(res);
    } else {
        n += snprintf(out + n, sizeof out - n, "DNS example.com : FALLITO (%d)\n", r);
    }
    int s = socket(AF_INET, SOCK_STREAM, 0);
    struct timeval tv = { .tv_sec = 4 };
    setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof tv);
    struct sockaddr_in a = { .sin_family = AF_INET, .sin_port = htons(80) };
    a.sin_addr.s_addr = inet_addr("1.1.1.1");
    int c = connect(s, (struct sockaddr *)&a, sizeof a);
    n += snprintf(out + n, sizeof out - n, "TCP 1.1.1.1:80 : %s (errno %d)\n", c == 0 ? "OK" : "FALLITO", c == 0 ? 0 : errno);
    close(s);
    httpd_resp_set_type(req, "text/plain");
    httpd_resp_send(req, out, n);
    return ESP_OK;
}


/* ---- Pagina filtro di cattura (regole testuali, tabelle in PSRAM) ---- */
static void send_escaped(httpd_req_t *req, const char *s, size_t max)
{
    char buf[256]; size_t o = 0;
    for (size_t i = 0; s[i] && i < max; i++) {
        const char *r = NULL;
        if (s[i] == '&') r = "&amp;"; else if (s[i] == '<') r = "&lt;"; else if (s[i] == '>') r = "&gt;";
        size_t l = r ? strlen(r) : 1;
        if (o + l >= sizeof buf) { httpd_resp_send_chunk(req, buf, o); o = 0; }
        if (r) { memcpy(buf + o, r, l); o += l; } else buf[o++] = s[i];
    }
    if (o) httpd_resp_send_chunk(req, buf, o);
}


static esp_err_t send_filter_page(httpd_req_t *req, const char *msg, bool ok)
{
    char b[900];
    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr_chunk(req,
      "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
      "<title>Filtro cattura</title><body style='font-family:sans-serif;max-width:820px;margin:1em auto;padding:0 8px'>"
      "<h2>Filtro di cattura</h2><p><a href=/>&larr; pannello</a></p>");
    if (msg[0]) {
        httpd_resp_sendstr_chunk(req, ok ? "<pre style='background:#dfd;padding:.5em;white-space:pre-wrap'>"
                                         : "<pre style='background:#fdd;padding:.5em;white-space:pre-wrap'>");
        send_escaped(req, msg, 1500);
        httpd_resp_sendstr_chunk(req, "</pre>");
    }
    httpd_resp_sendstr_chunk(req, "<textarea id=t rows=24 style='width:100%;font-family:monospace' spellcheck=false>");
    send_escaped(req, filter_get_text(), FILTER_MAX_TEXT);
    httpd_resp_sendstr_chunk(req,
      "</textarea><br>"
      "<button onclick=\"fetch('/filter',{method:'POST',body:document.getElementById('t').value}).then(r=>r.text()).then(h=>{document.open();document.write(h);document.close()})\">Salva e applica</button> "
      "<button onclick=\"fetch('/filter/default').then(r=>r.text()).then(x=>{document.getElementById('t').value=x})\">Carica regole predefinite</button> "
      "<a href=/filter>ricarica</a>");

    filter_stats_t fs; filter_get_stats(&fs);
    size_t rt = 0, rf = 0; uint32_t nousb = 0; capture_get_ring(&rt, &rf, &nousb);
    snprintf(b, sizeof b,
      "<p>Filtro <b>%s</b> | %d regole (%d di dominio) | default <b>%s</b> | snaplen <b>%u</b><br>"
      "Frame scartati dal filtro: <b>%lu</b> | tenuti: <b>%lu</b> | IP appresi dal DNS: <b>%lu</b><br>"
      "PSRAM libera: <b>%u KB</b> su %u KB | buffer cattura: %u KB liberi su %u KB | scartati senza USB: %lu</p>",
      fs.enabled ? "attivo" : "SPENTO", fs.nrules, fs.ndomains, fs.default_drop ? "drop" : "keep", fs.snaplen,
      (unsigned long)fs.dropped, (unsigned long)fs.kept, (unsigned long)fs.learned_ips,
      (unsigned)(heap_caps_get_free_size(MALLOC_CAP_SPIRAM) / 1024),
      (unsigned)(heap_caps_get_total_size(MALLOC_CAP_SPIRAM) / 1024),
      (unsigned)(rf / 1024), (unsigned)(rt / 1024), (unsigned long)nousb);
    httpd_resp_sendstr_chunk(req, b);

    httpd_resp_sendstr_chunk(req,
      "<pre style='background:#f4f4f4;padding:.6em;font-size:90%'>"
      "Una regola per riga, '#' = commento, la prima che combacia vince (i domini hanno la posizione della loro riga).\n"
      "  default keep|drop            cosa fare se nessuna regola combacia\n"
      "  snaplen N                    byte catturati per frame (64..1600)\n"
      "  drop|keep ip|src|dst  A.B.C.D | CIDR     (piu' valori sulla stessa riga)\n"
      "  drop|keep port|sport|dport  N | N-M\n"
      "  drop|keep proto  tcp udp icmp arp ipv6\n"
      "  drop|keep domain  nome ...   suffisso di dominio; gli IP si imparano dalle risposte DNS dell'AP\n"
      "Esempi:  drop domain google.com | drop port 853 | keep ip 93.184.216.34 (con 'default drop')</pre>"
      "<table border=1 cellpadding=3 style='border-collapse:collapse'><tr><th>riga</th><th>regola</th><th>corrispondenze</th></tr>");
    int nr = filter_rule_count(), shown = 0, last_line = -1;
    for (int i = 0; i < nr && shown < 80; i++) {
        int line = 0; uint32_t hits = 0;
        if (!filter_rule_info(i, &line, &hits) || !hits) continue;
        char desc[128];
        if (!filter_rule_desc(i, desc, sizeof desc)) continue;
        snprintf(b, sizeof b, "<tr><td>%d</td><td><code>", line);
        httpd_resp_sendstr_chunk(req, b);
        send_escaped(req, desc, strlen(desc));
        snprintf(b, sizeof b, "</code></td><td>%lu</td></tr>", (unsigned long)hits);
        httpd_resp_sendstr_chunk(req, b);
        shown++; last_line = line;
    }
    (void)last_line;
    httpd_resp_sendstr_chunk(req, "</table></body>");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t filter_get(httpd_req_t *req) { return send_filter_page(req, "", false); }

static esp_err_t filter_default_get(httpd_req_t *req)
{
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    return httpd_resp_sendstr(req, filter_default_text());
}

static esp_err_t filter_post(httpd_req_t *req)
{
    if (req->content_len > FILTER_MAX_TEXT) return send_filter_page(req, "Testo troppo lungo (max 65536 byte).", false);
    char *body = psram_alloc(req->content_len + 1);
    char *rep = psram_alloc(2048);
    if (!body || !rep) { free(body); free(rep); return httpd_resp_send_500(req); }
    size_t got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, body + got, req->content_len - got);
        if (r <= 0) { free(body); free(rep); return ESP_FAIL; }
        got += r;
    }
    body[got] = 0;
    int errs = filter_apply_text(body, true, rep, 2048);
    esp_err_t res = send_filter_page(req, rep, errs == 0);
    free(body); free(rep);
    return res;
}

/* ---- Pagina rete Ethernet: DHCP / IP fisso, salvato in NVS, applicabile a caldo o al riavvio ---- */
typedef enum { DEF_APPLY = 1, DEF_REBOOT = 2 } deferred_t;

static void deferred_task(void *arg)
{
    deferred_t what = (deferred_t)(intptr_t)arg;
    vTaskDelay(pdMS_TO_TICKS(800));            /* lascia uscire la risposta HTTP prima di toccare la rete */
    if (what == DEF_REBOOT) {
        esp_restart();
    } else {
        esp_netif_t *eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
        esp_err_t e = netcfg_eth_apply(eth, true);
        ESP_LOGI(TAG, "applicazione a caldo rete Ethernet -> %s", esp_err_to_name(e));
        eth_cfg_t c; netcfg_eth_get(&c);
        if (c.use_static) net_nat_apply();     /* con DHCP lo fa l'evento "got ip" quando arriva il lease */
    }
    vTaskDelete(NULL);
}

static void run_deferred(deferred_t what)
{
    if (xTaskCreate(deferred_task, "net_apply", 4096, (void *)(intptr_t)what, 5, NULL) != pdPASS)
        ESP_LOGE(TAG, "impossibile creare il task di applicazione rete");
}

static void html_attr(httpd_req_t *req, const char *s)      /* valore sicuro dentro value='...' */
{
    char o[96]; size_t k = 0;
    for (; *s && k < sizeof o - 7; s++) {
        if (*s == '\'' || *s == '<' || *s == '>' || *s == '&' || *s == '"') k += snprintf(o + k, sizeof o - k, "&#%d;", *s);
        else o[k++] = *s;
    }
    httpd_resp_send_chunk(req, o, k);
}

static esp_err_t net_page(httpd_req_t *req, const char *msg, bool ok, const eth_cfg_t *form)
{
    char b[640];
    eth_cfg_t sv; netcfg_eth_get(&sv);
    const eth_cfg_t *f = form ? form : &sv;

    /* stato reale del netif */
    esp_netif_t *eth = esp_netif_get_handle_from_ifkey("ETH_DEF");
    esp_netif_ip_info_t ip = {0}; esp_netif_dns_info_t dns = {0};
    esp_netif_dhcp_status_t ds = ESP_NETIF_DHCP_INIT;
    bool up = false;
    if (eth) {
        esp_netif_get_ip_info(eth, &ip);
        esp_netif_get_dns_info(eth, ESP_NETIF_DNS_MAIN, &dns);
        esp_netif_dhcpc_get_status(eth, &ds);
        up = esp_netif_is_netif_up(eth);
    }
    bool run_dhcp = (ds == ESP_NETIF_DHCP_STARTED);
    uint32_t ipa = ntohl(ip.ip.addr);

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr_chunk(req,
      "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
      "<title>Rete Ethernet</title><body style='font-family:sans-serif;max-width:680px;margin:1em auto;padding:0 8px'>"
      "<h2>Rete Ethernet (ENC28J60)</h2><p><a href=/>&larr; pannello</a> | <a href=/net>aggiorna</a></p>");
    if (msg && msg[0]) {
        httpd_resp_sendstr_chunk(req, ok ? "<pre style='background:#dfd;padding:.5em;white-space:pre-wrap'>"
                                         : "<pre style='background:#fdd;padding:.5em;white-space:pre-wrap'>");
        send_escaped(req, msg, 600);
        httpd_resp_sendstr_chunk(req, "</pre>");
    }
    snprintf(b, sizeof b,
      "<h3>Stato attuale</h3><p>Modalit&agrave;: <b>%s</b> | link: <b>%s</b><br>"
      "IP <b>" IPSTR "</b> | maschera " IPSTR " | gateway " IPSTR " | DNS " IPSTR "</p>",
      run_dhcp ? "DHCP" : "IP fisso", up ? "su" : "gi&ugrave;",
      IP2STR(&ip.ip), IP2STR(&ip.netmask), IP2STR(&ip.gw), IP2STR(&dns.ip.u_addr.ip4));
    httpd_resp_sendstr_chunk(req, b);
    if (up && ipa && (ipa & 0xFFFFFF00u) == 0xC0A80400u)
        httpd_resp_sendstr_chunk(req, "<p style='background:#fed;padding:.4em'>Attenzione: la rete Ethernet &egrave; 192.168.4.x, "
                                      "come l'access point: il NAT non pu&ograve; funzionare. Cambia la rete del router o usa un IP fisso diverso.</p>");

    httpd_resp_sendstr_chunk(req,
      "<h3>Imposta</h3><form method=post action=/net>"
      "<label><input type=radio name=mode value=dhcp id=md");
    httpd_resp_sendstr_chunk(req, f->use_static ? ">" : " checked>");
    httpd_resp_sendstr_chunk(req,
      " DHCP</label> <small>(l'IP lo assegna il router)</small><br>"
      "<label><input type=radio name=mode value=static id=ms");
    httpd_resp_sendstr_chunk(req, f->use_static ? " checked>" : ">");
    httpd_resp_sendstr_chunk(req, " IP fisso</label><table style='margin:.4em 0 .4em 1.5em'>");
    static const char *lbl[4] = { "IP", "Maschera", "Gateway", "DNS (vuoto = gateway)" };
    static const char *nm[4]  = { "ip", "mask", "gw", "dns" };
    const char *val[4] = { f->ip, f->mask, f->gw, f->dns };
    for (int i = 0; i < 4; i++) {
        snprintf(b, sizeof b, "<tr><td>%s<td><input name=%s size=16 maxlength=15 value='", lbl[i], nm[i]);
        httpd_resp_sendstr_chunk(req, b);
        html_attr(req, val[i]);
        httpd_resp_sendstr_chunk(req, "'>");
    }
    httpd_resp_sendstr_chunk(req,
      "</table>"
      "<button name=act value=now>Salva e applica ora</button> "
      "<button name=act value=save>Salva (vale dal prossimo riavvio)</button> "
      "<button name=act value=reboot>Salva e riavvia</button></form>"
      "<script>function t(){var s=document.getElementById('ms').checked;"
      "['ip','mask','gw','dns'].forEach(function(n){document.getElementsByName(n)[0].disabled=!s})}"
      "document.getElementById('md').onchange=document.getElementById('ms').onchange=t;t();</script>"
      "<p><small>Applicando a caldo, se sei collegato via Ethernet perderai la pagina: riaprila al nuovo IP "
      "(con DHCP lo vedi qui sopra dal Wi-Fi \"LoggerWIFI\", pannello su <b>http://192.168.4.1/net</b>). "
      "Il Wi-Fi dell'access point non viene interrotto. Passando a DHCP gli ultimi valori fissi restano salvati.</small></p>");

    /* cosa c'e' davvero in flash (riletto ora da NVS, non dalla RAM) */
    eth_cfg_t ne; bool have_e = netcfg_eth_read_nvs(&ne);
    ap_cfg_t na; bool have_a = netcfg_ap_read_nvs(&na);
    httpd_resp_sendstr_chunk(req, "<h3>Contenuto di NVS (namespace <code>netcfg</code>)</h3><pre style='background:#f4f4f4;padding:.6em'>");
    if (have_e) snprintf(b, sizeof b, "eth_mode = %s\neth_ip   = %s\neth_mask = %s\neth_gw   = %s\neth_dns  = %s\n",
                         ne.use_static ? "1 (IP fisso)" : "0 (DHCP)", ne.ip, ne.mask, ne.gw, ne.dns);
    else        snprintf(b, sizeof b, "Ethernet: nessun valore salvato -> al boot si usa il predefinito (IP fisso 192.168.137.200)\n");
    send_escaped(req, b, sizeof b);
    if (have_a) snprintf(b, sizeof b, "ap_ssid  = %s\nap_ch    = %u\nap_dbm   = %u\nap_hid   = %u\n", na.ssid, na.channel, na.tx_dbm, na.hidden);
    else        snprintf(b, sizeof b, "AP: nessun valore salvato -> al boot si usa il predefinito (LoggerWIFI, canale 6, 8 dBm)\n");
    send_escaped(req, b, sizeof b);
    httpd_resp_sendstr_chunk(req,
      "</pre><p><a href=/net/reset onclick=\"return confirm('Cancellare la configurazione di rete salvata e riavviare?')\">"
      "Ripristina predefiniti (cancella NVS e riavvia)</a></p></body>");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t net_get(httpd_req_t *req) { return net_page(req, "", false, NULL); }

static esp_err_t net_post(httpd_req_t *req)
{
    char body[400];
    if (req->content_len == 0 || req->content_len >= sizeof body) return net_page(req, "Richiesta non valida.", false, NULL);
    size_t got = 0;
    while (got < req->content_len) {
        int r = httpd_req_recv(req, body + got, req->content_len - got);
        if (r <= 0) return ESP_FAIL;
        got += (size_t)r;
    }
    body[got] = 0;

    eth_cfg_t c; netcfg_eth_get(&c);            /* parte dai valori salvati: in DHCP i campi fissi si conservano */
    char v[40];
    if (httpd_query_key_value(body, "mode", v, sizeof v) != ESP_OK) return net_page(req, "Scegli DHCP o IP fisso.", false, NULL);
    c.use_static = strcmp(v, "static") == 0;
    if (c.use_static) {
        struct { const char *k; char *dst; size_t sz; } f[4] = {
            { "ip", c.ip, sizeof c.ip }, { "mask", c.mask, sizeof c.mask },
            { "gw", c.gw, sizeof c.gw }, { "dns", c.dns, sizeof c.dns } };
        for (int i = 0; i < 4; i++) {
            f[i].dst[0] = 0;
            if (httpd_query_key_value(body, f[i].k, v, sizeof v) == ESP_OK) {
                urldecode(v);
                strncpy(f[i].dst, v, f[i].sz - 1); f[i].dst[f[i].sz - 1] = 0;
            }
        }
    }
    char act[12] = "now";
    httpd_query_key_value(body, "act", act, sizeof act);

    char err[160] = "";
    if (!netcfg_eth_set(&c, err, sizeof err)) return net_page(req, err, false, &c);

    char msg[320];
    if (strcmp(act, "reboot") == 0) {
        snprintf(msg, sizeof msg, "Salvato in NVS e verificato. Riavvio tra un istante...");
        run_deferred(DEF_REBOOT);
    } else if (strcmp(act, "save") == 0) {
        snprintf(msg, sizeof msg, "Salvato in NVS e verificato. Sara' applicato al prossimo riavvio (la rete attuale non e' cambiata).");
    } else {
        snprintf(msg, sizeof msg, "Salvato in NVS e verificato. Applicazione in corso: la rete Ethernet cambia tra un istante%s",
                 c.use_static ? "." : " (con DHCP l'IP assegnato apparira' in 'Stato attuale').");
        run_deferred(DEF_APPLY);
    }
    return net_page(req, msg, true, NULL);
}

static esp_err_t net_reset_get(httpd_req_t *req)
{
    bool ok = netcfg_erase();
    httpd_resp_set_type(req, "text/plain; charset=utf-8");
    httpd_resp_sendstr(req, ok ? "Configurazione di rete cancellata. Riavvio con i predefiniti (IP fisso 192.168.137.200, AP LoggerWIFI)..."
                               : "Cancellazione fallita.");
    if (ok) run_deferred(DEF_REBOOT);
    return ESP_OK;
}

/* ---- Pagina Wireshark: comandi da lanciare SUL PC per leggere lo stream pcap dalla USB nativa ---- */
static esp_err_t wireshark_get(httpd_req_t *req)
{
    char b[700];
    bool uc = false; uint32_t wf = 0, wb = 0, ws = 0, cap = 0, drop = 0, nousb = 0;
    size_t rt = 0, rf = 0;
    capture_get_usb_stats(&uc, &wf, &wb, &ws);
    capture_get_stats(&cap, &drop);
    capture_get_ring(&rt, &rf, &nousb);

    httpd_resp_set_type(req, "text/html; charset=utf-8");
    httpd_resp_sendstr_chunk(req,
      "<!doctype html><meta charset=utf-8><meta name=viewport content='width=device-width'>"
      "<title>Cattura su Wireshark</title><body style='font-family:sans-serif;max-width:820px;margin:1em auto;padding:0 8px'>"
      "<h2>Cattura su Wireshark (USB nativa)</h2><p><a href=/>&larr; pannello</a> | <a href=/wireshark>aggiorna</a></p>");
    snprintf(b, sizeof b,
      "<p>Stato: USB connessa <b>%s</b> | frame inviati al PC <b>%lu</b> (%lu B) | frame in coda <b>%lu</b> | "
      "buffer libero %u KB su %u KB | scartati senza USB <b>%lu</b></p>",
      uc ? "s&igrave;" : "no", (unsigned long)wf, (unsigned long)wb, (unsigned long)cap,
      (unsigned)(rf / 1024), (unsigned)(rt / 1024), (unsigned long)nousb);
    httpd_resp_sendstr_chunk(req, b);
    httpd_resp_sendstr_chunk(req,
      "<p>Lo script gira <b>sul PC</b>, non sull'ESP: la pagina non pu&ograve; avviarlo, ti d&agrave; il comando da copiare.<br>"
      "Collega il PC al connettore <b>USB nativo</b> della scheda (quello che compare come "
      "<i>USB JTAG/serial debug unit</i>, non la porta UART) e chiudi eventuali monitor seriali aperti su quella porta: "
      "una porta COM pu&ograve; essere aperta da un solo programma.</p>"
      "<p>Prima volta: <code>pip install pyserial</code>. Lancia i comandi dalla cartella che contiene <code>pcap_bridge.py</code> (<code>tools</code>).</p>"
      "<p>Porta del PC: <input id=p value=COM7 size=12 oninput=u()> "
      "<small>(Gestione dispositivi &rarr; Porte: <i>USB JTAG/serial debug unit</i>)</small></p>"

      "<h3>Wireshark in diretta &mdash; Prompt dei comandi (cmd)</h3>"
      "<pre id=c1 style='background:#f4f4f4;padding:.6em;white-space:pre-wrap'>python pcap_bridge.py <span class=p>COM7</span> | \"C:\\Program Files\\Wireshark\\Wireshark.exe\" -k -i -</pre>"
      "<button onclick=\"cp('c1')\">Copia</button>"

      "<h3>Wireshark in diretta &mdash; PowerShell</h3>"
      "<pre id=c2 style='background:#f4f4f4;padding:.6em;white-space:pre-wrap'>cmd /c 'python pcap_bridge.py <span class=p>COM7</span> | \"C:\\Program Files\\Wireshark\\Wireshark.exe\" -k -i -'</pre>"
      "<button onclick=\"cp('c2')\">Copia</button> "
      "<small>(in PowerShell la pipe diretta rovina i dati binari: serve <code>cmd /c</code>)</small>"

      "<h3>Solo salvataggio su file</h3>"
      "<pre id=c3 style='background:#f4f4f4;padding:.6em;white-space:pre-wrap'>python pcap_bridge.py <span class=p>COM7</span> --out cattura.pcap</pre>"
      "<button onclick=\"cp('c3')\">Copia</button> <small>(si ferma con Ctrl+C; poi apri il file con Wireshark)</small>"

      "<h3>Linux / macOS</h3>"
      "<pre id=c4 style='background:#f4f4f4;padding:.6em;white-space:pre-wrap'>python3 pcap_bridge.py /dev/ttyACM0 | wireshark -k -i -</pre>"
      "<button onclick=\"cp('c4')\">Copia</button> <small>(la porta pu&ograve; essere /dev/ttyACM0 o /dev/cu.usbmodem...)</small>"

      "<p><small>Se Wireshark &egrave; installato altrove, cambia il percorso. Il filtro di cattura si imposta in "
      "<a href=/filter>Filtro di cattura</a>. Con la USB scollegata i frame vengono scartati (contatore qui sopra).</small></p>"
      "<script>"
      "function u(){var v=document.getElementById('p').value||'COM7';"
      "var a=document.getElementsByClassName('p');for(var i=0;i<a.length;i++)a[i].textContent=v;"
      "try{localStorage.setItem('wsport',v)}catch(e){}}"
      "function cp(id){var e=document.getElementById(id);"
      "try{if(navigator.clipboard&&window.isSecureContext){navigator.clipboard.writeText(e.innerText);return}}catch(x){}"
      "var r=document.createRange();r.selectNode(e);var s=getSelection();s.removeAllRanges();s.addRange(r);"
      "try{document.execCommand('copy')}catch(x){}}"
      "try{var v=localStorage.getItem('wsport');if(v)document.getElementById('p').value=v}catch(e){}u();"
      "</script></body>");
    httpd_resp_sendstr_chunk(req, NULL);
    return ESP_OK;
}

static esp_err_t restart_get(httpd_req_t *req)
{
    httpd_resp_sendstr(req, "riavvio...");
    vTaskDelay(pdMS_TO_TICKS(300));
    esp_restart();
    return ESP_OK;
}

void webcfg_start(void)
{
    httpd_config_t cfg = HTTPD_DEFAULT_CONFIG();
    cfg.stack_size = 8192;
    cfg.max_uri_handlers = 20;
    httpd_handle_t h = NULL;
    if (httpd_start(&h, &cfg) != ESP_OK) { ESP_LOGE(TAG, "httpd_start fallita"); return; }
    httpd_uri_t u1 = { .uri = "/",        .method = HTTP_GET, .handler = root_get };
    httpd_uri_t u2 = { .uri = "/set",     .method = HTTP_GET, .handler = set_get };
    httpd_uri_t u3 = { .uri = "/restart", .method = HTTP_GET, .handler = restart_get };
    httpd_register_uri_handler(h, &u1);
    httpd_register_uri_handler(h, &u2);
    httpd_register_uri_handler(h, &u3);
    httpd_uri_t u6 = { .uri = "/filter",  .method = HTTP_GET,  .handler = filter_get };
    httpd_uri_t u7 = { .uri = "/filter",  .method = HTTP_POST, .handler = filter_post };
    httpd_register_uri_handler(h, &u6);
    httpd_register_uri_handler(h, &u7);
    httpd_uri_t u8 = { .uri = "/filter/default", .method = HTTP_GET, .handler = filter_default_get };
    httpd_register_uri_handler(h, &u8);
    httpd_uri_t u5 = { .uri = "/nettest", .method = HTTP_GET, .handler = nettest_get };
    httpd_register_uri_handler(h, &u5);
    httpd_uri_t u4 = { .uri = "/toggle",  .method = HTTP_GET, .handler = toggle_get };
    httpd_register_uri_handler(h, &u4);
    httpd_uri_t n1 = { .uri = "/net",       .method = HTTP_GET,  .handler = net_get };
    httpd_uri_t n2 = { .uri = "/net",       .method = HTTP_POST, .handler = net_post };
    httpd_uri_t n3 = { .uri = "/net/reset", .method = HTTP_GET,  .handler = net_reset_get };
    httpd_register_uri_handler(h, &n1);
    httpd_register_uri_handler(h, &n2);
    httpd_register_uri_handler(h, &n3);
    httpd_uri_t w1 = { .uri = "/wireshark", .method = HTTP_GET, .handler = wireshark_get };
    httpd_register_uri_handler(h, &w1);
    ESP_LOGI(TAG, "Pannello web attivo sulla porta 80");
}
