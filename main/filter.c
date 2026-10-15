#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <limits.h>
#include <stdarg.h>
#include <strings.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "nvs.h"
#include "lwip/pbuf.h"
#include "filter.h"

static const char *TAG = "FILTER";

#define MAX_RULES   4096
#define DYN_N       8192            /* voci della tabella IP appresi (potenza di 2) */
#define DYN_PROBE   8
#define NVS_NS      "sniffer"
#define NVS_KEY     "rules"

enum { K_IP, K_SRC, K_DST, K_PORT, K_SPORT, K_DPORT, K_PROTO, K_DOMAIN };
enum { PR_TCP = 6, PR_UDP = 17, PR_ICMP = 1, PR_ARP = 200, PR_IPV6 = 201 };

typedef struct {
    uint8_t  drop;      /* 1 = drop, 0 = keep */
    uint8_t  kind;
    uint16_t line;
    uint32_t a, m;      /* IP e maschera; oppure offset del dominio nel pool (a) e lunghezza (m) */
    uint16_t p1, p2;    /* intervallo porte; p1 = protocollo per K_PROTO */
    uint32_t hits;
} rule_t;

typedef struct {
    rule_t  *rules;
    int      n;
    int     *dom_idx;          /* indici delle regole di tipo dominio */
    int      ndom;
    char    *pool;             /* stringhe dei domini */
    size_t   pool_len;
    bool     default_drop;
    uint16_t snaplen;
    uint16_t gen;
    char    *text;
} ruleset_t;

typedef struct { uint32_t ip; uint32_t exp; uint16_t idx; uint16_t gen; } dyn_t;

static ruleset_t *volatile s_rs = NULL;
static dyn_t     *s_dyn = NULL;
static volatile bool s_enabled = true;
static volatile uint32_t s_dropped, s_kept, s_learned;
static uint16_t s_gen_counter = 1;

/* ---------------------------------------------------------------- utilita' */
void *psram_alloc(size_t n)
{
    void *p = heap_caps_malloc(n, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
    if (!p) p = malloc(n);
    return p;
}

/* ---------------------------------------------------------------- testo predefinito */
static const char DEFAULT_TEXT[] =
"# Filtro di cattura - una regola per riga, '#' = commento.\n"
"# Prima regola che combacia vince.  Sintassi:\n"
"#   default keep|drop           cosa fare se nessuna regola combacia\n"
"#   snaplen N                   byte catturati per frame (64..1600)\n"
"#   drop|keep ip|src|dst  A.B.C.D  oppure CIDR A.B.C.D/N  (piu' valori sulla stessa riga)\n"
"#   drop|keep port|sport|dport  N oppure N-M\n"
"#   drop|keep proto  tcp udp icmp arp ipv6\n"
"#   drop|keep domain  nome  (suffisso: google.com vale anche per www.google.com;\n"
"#                            gli IP vengono appresi dalle risposte DNS)\n"
"default keep\n"
"snaplen 1600\n"
"\n"
"# --- Google lato Android: per nome (appreso dal DNS) ---\n"
"drop domain google.com googleapis.com gstatic.com gvt1.com gvt2.com googleusercontent.com\n"
"drop domain ggpht.com android.com youtube.com ytimg.com googlevideo.com 1e100.net\n"
"drop domain doubleclick.net googlesyndication.com google-analytics.com app-measurement.com\n"
"\n"
"# --- Google: intervalli IP principali ---\n"
"drop ip 8.8.4.0/24 8.8.8.0/24 64.233.160.0/19 66.102.0.0/20 66.249.64.0/19 72.14.192.0/18\n"
"drop ip 74.125.0.0/16 108.177.0.0/17 142.250.0.0/15 172.217.0.0/16 172.253.0.0/16\n"
"drop ip 173.194.0.0/16 192.178.0.0/15 209.85.128.0/17 216.58.192.0/19 216.239.32.0/19\n"
"drop ip 108.170.192.0/18\n";

const char *filter_default_text(void) { return DEFAULT_TEXT; }

/* ---------------------------------------------------------------- parser */
static bool parse_ip(const char *s, uint32_t *ip, uint32_t *mask)
{
    unsigned a, b, c, d, n = 32; int used = 0;
    if (sscanf(s, "%u.%u.%u.%u%n", &a, &b, &c, &d, &used) != 4) return false;
    if (a > 255 || b > 255 || c > 255 || d > 255) return false;
    if (s[used] == '/') {
        if (sscanf(s + used + 1, "%u", &n) != 1 || n > 32) return false;
    } else if (s[used] != 0) {
        return false;
    }
    *ip = (a << 24) | (b << 16) | (c << 8) | d;
    *mask = n ? (0xFFFFFFFFu << (32 - n)) : 0;
    *ip &= *mask;
    return true;
}

static bool parse_port(const char *s, uint16_t *lo, uint16_t *hi)
{
    unsigned a, b; int used = 0;
    if (sscanf(s, "%u%n", &a, &used) != 1 || a > 65535) return false;
    b = a;
    if (s[used] == '-') {
        if (sscanf(s + used + 1, "%u", &b) != 1 || b > 65535 || b < a) return false;
    } else if (s[used] != 0) {
        return false;
    }
    *lo = a; *hi = b;
    return true;
}

static void rep(char *report, size_t len, size_t *pos, const char *fmt, ...) __attribute__((format(printf, 4, 5)));
static void rep(char *report, size_t len, size_t *pos, const char *fmt, ...)
{
    if (!report || *pos >= len) return;
    va_list ap; va_start(ap, fmt);
    int n = vsnprintf(report + *pos, len - *pos, fmt, ap);
    va_end(ap);
    if (n > 0) *pos += (size_t)n;
    if (*pos >= len) *pos = len - 1;
}

static ruleset_t *build_ruleset(const char *text, char *report, size_t report_len, int *errors)
{
    size_t rp = 0;
    if (report && report_len) report[0] = 0;
    int err = 0;

    ruleset_t *rs = calloc(1, sizeof *rs);
    if (!rs) return NULL;
    rs->rules   = psram_alloc(sizeof(rule_t) * MAX_RULES);
    rs->dom_idx = psram_alloc(sizeof(int) * MAX_RULES);
    rs->pool    = psram_alloc(FILTER_MAX_TEXT + 16);
    rs->text    = psram_alloc(strlen(text) + 1);
    if (!rs->rules || !rs->dom_idx || !rs->pool || !rs->text) {
        free(rs->rules); free(rs->dom_idx); free(rs->pool); free(rs->text); free(rs);
        return NULL;
    }
    strcpy(rs->text, text);
    rs->snaplen = 1600;
    rs->gen = s_gen_counter++;
    if (s_gen_counter == 0) s_gen_counter = 1;

    char *copy = strdup(text);
    if (!copy) { err = 1; *errors = err; return rs; }
    int lineno = 0;
    char *cur = copy;
    while (cur) {                                /* niente strtok: le righe vuote devono contare */
        char *line = cur;
        char *nl = strchr(cur, '\n');
        if (nl) { *nl = 0; cur = nl + 1; } else cur = NULL;
        lineno++;
        int err_before = err;
        char *hash = strchr(line, '#'); if (hash) *hash = 0;
        for (char *q = line; *q; q++) if (*q == ',' || *q == '\r' || *q == '\t') *q = ' ';
        char *tok_save = NULL;
        char *t0 = strtok_r(line, " ", &tok_save);
        if (!t0) continue;
        for (char *q = t0; *q; q++) *q = tolower((unsigned char)*q);

        if (!strcmp(t0, "default")) {
            char *v = strtok_r(NULL, " ", &tok_save);
            if (v && !strcasecmp(v, "drop")) rs->default_drop = true;
            else if (v && !strcasecmp(v, "keep")) rs->default_drop = false;
            else { err++; rep(report, report_len, &rp, "riga %d: 'default' vuole keep o drop\n", lineno); }
            continue;
        }
        if (!strcmp(t0, "snaplen")) {
            char *v = strtok_r(NULL, " ", &tok_save);
            int n = v ? atoi(v) : 0;
            if (n >= 64 && n <= 1600) rs->snaplen = (uint16_t)n;
            else { err++; rep(report, report_len, &rp, "riga %d: snaplen deve essere 64..1600\n", lineno); }
            continue;
        }
        bool drop;
        if (!strcmp(t0, "drop")) drop = true;
        else if (!strcmp(t0, "keep")) drop = false;
        else { err++; rep(report, report_len, &rp, "riga %d: comando sconosciuto '%s'\n", lineno, t0); continue; }

        char *kw = strtok_r(NULL, " ", &tok_save);
        if (!kw) { err++; rep(report, report_len, &rp, "riga %d: manca il campo\n", lineno); continue; }
        for (char *q = kw; *q; q++) *q = tolower((unsigned char)*q);
        int kind = -1;
        if (!strcmp(kw, "ip")) kind = K_IP;
        else if (!strcmp(kw, "src")) kind = K_SRC;
        else if (!strcmp(kw, "dst")) kind = K_DST;
        else if (!strcmp(kw, "port")) kind = K_PORT;
        else if (!strcmp(kw, "sport")) kind = K_SPORT;
        else if (!strcmp(kw, "dport")) kind = K_DPORT;
        else if (!strcmp(kw, "proto")) kind = K_PROTO;
        else if (!strcmp(kw, "domain")) kind = K_DOMAIN;
        else { err++; rep(report, report_len, &rp, "riga %d: campo sconosciuto '%s'\n", lineno, kw); continue; }

        int nvals = 0;
        for (char *v = strtok_r(NULL, " ", &tok_save); v; v = strtok_r(NULL, " ", &tok_save)) {
            if (rs->n >= MAX_RULES) { err++; rep(report, report_len, &rp, "riga %d: troppe regole (max %d)\n", lineno, MAX_RULES); break; }
            rule_t r = { .drop = drop, .kind = (uint8_t)kind, .line = (uint16_t)lineno };
            bool ok = true;
            switch (kind) {
            case K_IP: case K_SRC: case K_DST:
                ok = parse_ip(v, &r.a, &r.m);
                break;
            case K_PORT: case K_SPORT: case K_DPORT:
                ok = parse_port(v, &r.p1, &r.p2);
                break;
            case K_PROTO:
                for (char *q = v; *q; q++) *q = tolower((unsigned char)*q);
                if (!strcmp(v, "tcp")) r.p1 = PR_TCP;
                else if (!strcmp(v, "udp")) r.p1 = PR_UDP;
                else if (!strcmp(v, "icmp")) r.p1 = PR_ICMP;
                else if (!strcmp(v, "arp")) r.p1 = PR_ARP;
                else if (!strcmp(v, "ipv6")) r.p1 = PR_IPV6;
                else ok = false;
                break;
            case K_DOMAIN: {
                const char *d = v;
                if (d[0] == '*' && d[1] == '.') d += 2;
                else if (d[0] == '.') d += 1;
                size_t dl = strlen(d);
                if (dl == 0 || dl > 200 || rs->pool_len + dl + 1 > FILTER_MAX_TEXT + 16) { ok = false; break; }
                r.a = (uint32_t)rs->pool_len; r.m = (uint32_t)dl;
                for (size_t i = 0; i < dl; i++) rs->pool[rs->pool_len + i] = tolower((unsigned char)d[i]);
                rs->pool[rs->pool_len + dl] = 0;
                rs->pool_len += dl + 1;
                break; }
            }
            if (!ok) { err++; rep(report, report_len, &rp, "riga %d: valore non valido '%s'\n", lineno, v); continue; }
            if (kind == K_DOMAIN) rs->dom_idx[rs->ndom++] = rs->n;
            rs->rules[rs->n++] = r;
            nvals++;
        }
        if (!nvals && err == err_before) { err++; rep(report, report_len, &rp, "riga %d: nessun valore\n", lineno); }
    }
    free(copy);
    *errors = err;
    return rs;
}

static void free_ruleset(ruleset_t *rs)
{
    if (!rs) return;
    free(rs->rules); free(rs->dom_idx); free(rs->pool); free(rs->text); free(rs);
}

/* ---------------------------------------------------------------- applica / NVS */
int filter_apply_text(const char *text, bool save, char *report, size_t report_len)
{
    if (strlen(text) > FILTER_MAX_TEXT) {
        if (report) snprintf(report, report_len, "testo troppo lungo (max %d byte)\n", FILTER_MAX_TEXT);
        return 1;
    }
    int errors = 0;
    ruleset_t *rs = build_ruleset(text, report, report_len, &errors);
    if (!rs) {
        if (report) snprintf(report, report_len, "memoria insufficiente\n");
        return 1;
    }
    ruleset_t *old = s_rs;
    s_rs = rs;                                   /* il thread di rete vede il nuovo set */
    if (old) { vTaskDelay(pdMS_TO_TICKS(100)); free_ruleset(old); }
    s_dropped = s_kept = 0;

    size_t l = report ? strlen(report) : 0;
    if (report && l < report_len)
        snprintf(report + l, report_len - l, "OK: %d regole (%d di dominio), snaplen %u, default %s, %d errori\n",
                 rs->n, rs->ndom, rs->snaplen, rs->default_drop ? "drop" : "keep", errors);
    ESP_LOGI(TAG, "regole applicate: %d (domini %d), errori %d", rs->n, rs->ndom, errors);

    if (save) {
        nvs_handle_t h;
        esp_err_t e = nvs_open(NVS_NS, NVS_READWRITE, &h);
        if (e == ESP_OK) {
            e = nvs_set_blob(h, NVS_KEY, text, strlen(text));
            if (e == ESP_OK) e = nvs_commit(h);
            nvs_close(h);
        }
        if (report && l < report_len) {
            size_t l2 = strlen(report);
            snprintf(report + l2, report_len - l2, e == ESP_OK ? "Salvato in flash (NVS).\n"
                                                              : "ATTENZIONE: salvataggio NVS fallito (%s)\n",
                     esp_err_to_name(e));
        }
    }
    return errors;
}

esp_err_t filter_init(void)
{
    s_dyn = psram_alloc(sizeof(dyn_t) * DYN_N);
    if (!s_dyn) return ESP_ERR_NO_MEM;
    memset(s_dyn, 0, sizeof(dyn_t) * DYN_N);

    char *text = NULL;
    nvs_handle_t h;
    if (nvs_open(NVS_NS, NVS_READONLY, &h) == ESP_OK) {
        size_t len = 0;
        if (nvs_get_blob(h, NVS_KEY, NULL, &len) == ESP_OK && len > 0 && len <= FILTER_MAX_TEXT) {
            text = malloc(len + 1);
            if (text && nvs_get_blob(h, NVS_KEY, text, &len) == ESP_OK) text[len] = 0;
            else { free(text); text = NULL; }
        }
        nvs_close(h);
    }
    char rep_buf[300];
    filter_apply_text(text ? text : DEFAULT_TEXT, false, rep_buf, sizeof rep_buf);
    ESP_LOGI(TAG, "%s (%s)", rep_buf, text ? "da NVS" : "predefinite");
    free(text);
    return ESP_OK;
}

const char *filter_get_text(void) { ruleset_t *r = s_rs; return r ? r->text : ""; }
uint16_t filter_snaplen(void) { ruleset_t *r = s_rs; return r ? r->snaplen : 1600; }
void filter_set_enabled(bool on) { s_enabled = on; }
bool filter_is_enabled(void) { return s_enabled; }

void filter_get_stats(filter_stats_t *s)
{
    ruleset_t *r = s_rs;
    memset(s, 0, sizeof *s);
    s->enabled = s_enabled;
    if (r) { s->nrules = r->n; s->ndomains = r->ndom; s->default_drop = r->default_drop; s->snaplen = r->snaplen; }
    s->learned_ips = s_learned; s->dropped = s_dropped; s->kept = s_kept;
}

int filter_rule_count(void) { ruleset_t *r = s_rs; return r ? r->n : 0; }
bool filter_rule_info(int idx, int *line, uint32_t *hits)
{
    ruleset_t *r = s_rs;
    if (!r || idx < 0 || idx >= r->n) return false;
    *line = r->rules[idx].line; *hits = r->rules[idx].hits;
    return true;
}

bool filter_rule_desc(int idx, char *out, size_t len)
{
    ruleset_t *r = s_rs;
    if (!r || idx < 0 || idx >= r->n) return false;
    const rule_t *x = &r->rules[idx];
    static const char *const kn[] = { "ip", "src", "dst", "port", "sport", "dport", "proto", "domain" };
    char v[96];
    switch (x->kind) {
    case K_IP: case K_SRC: case K_DST: {
        int bits = x->m ? 32 - __builtin_ctz(x->m) : 0;
        snprintf(v, sizeof v, "%u.%u.%u.%u/%d", (unsigned)(x->a >> 24), (unsigned)((x->a >> 16) & 255),
                 (unsigned)((x->a >> 8) & 255), (unsigned)(x->a & 255), bits);
        break; }
    case K_PORT: case K_SPORT: case K_DPORT:
        if (x->p1 == x->p2) snprintf(v, sizeof v, "%u", x->p1); else snprintf(v, sizeof v, "%u-%u", x->p1, x->p2);
        break;
    case K_PROTO:
        snprintf(v, sizeof v, "%s", x->p1 == PR_TCP ? "tcp" : x->p1 == PR_UDP ? "udp" : x->p1 == PR_ICMP ? "icmp" :
                                    x->p1 == PR_ARP ? "arp" : "ipv6");
        break;
    default:
        snprintf(v, sizeof v, "%.*s", (int)(x->m > 80 ? 80 : x->m), r->pool + x->a);
        break;
    }
    snprintf(out, len, "%s %s %s", x->drop ? "drop" : "keep", kn[x->kind], v);
    return true;
}

/* ---------------------------------------------------------------- IP appresi dal DNS */
static inline uint32_t dyn_hash(uint32_t ip) { return (ip * 2654435761u) >> 19; }

static int dyn_lookup(uint32_t ip, uint16_t gen, uint32_t now)
{
    uint32_t h = dyn_hash(ip);
    for (int i = 0; i < DYN_PROBE; i++) {
        const dyn_t *e = &s_dyn[(h + i) & (DYN_N - 1)];
        if (e->ip == ip && e->gen == gen && e->exp > now) return e->idx;
    }
    return INT_MAX;
}

static void dyn_insert(uint32_t ip, int idx, uint16_t gen, uint32_t now, uint32_t ttl)
{
    if (ttl < 300) ttl = 300;
    if (ttl > 3600) ttl = 3600;
    uint32_t h = dyn_hash(ip);
    dyn_t *slot = NULL;
    for (int i = 0; i < DYN_PROBE; i++) {
        dyn_t *e = &s_dyn[(h + i) & (DYN_N - 1)];
        if (e->ip == ip) { slot = e; break; }
        if (!slot && (e->ip == 0 || e->gen != gen || e->exp <= now)) slot = e;
    }
    if (!slot) slot = &s_dyn[h & (DYN_N - 1)];
    if (slot->ip != ip) s_learned++;
    slot->ip = ip; slot->idx = (uint16_t)idx; slot->gen = gen; slot->exp = now + ttl;
}

/* ---------------------------------------------------------------- DNS */
static int dns_name(const uint8_t *b, int len, int off, char *out, int outlen, int *next)
{
    int pos = off, jumps = 0, o = 0, nxt = -1;
    for (;;) {
        if (pos >= len) return -1;
        uint8_t c = b[pos];
        if (c == 0) { pos++; if (nxt < 0) nxt = pos; break; }
        if ((c & 0xC0) == 0xC0) {
            if (pos + 1 >= len) return -1;
            int ptr = ((c & 0x3F) << 8) | b[pos + 1];
            if (nxt < 0) nxt = pos + 2;
            if (++jumps > 8) return -1;
            pos = ptr;
            continue;
        }
        if (c & 0xC0) return -1;
        pos++;
        if (pos + c > len) return -1;
        if (o && o < outlen - 1) out[o++] = '.';
        for (int i = 0; i < c; i++) if (o < outlen - 1) out[o++] = tolower(b[pos + i]);
        pos += c;
    }
    out[o] = 0;
    *next = nxt;
    return 0;
}

static int domain_match(const ruleset_t *rs, const char *name)
{
    size_t nl = strlen(name);
    for (int k = 0; k < rs->ndom; k++) {
        const rule_t *r = &rs->rules[rs->dom_idx[k]];
        const char *pat = rs->pool + r->a; size_t pl = r->m;
        if ((nl == pl && !memcmp(name, pat, pl)) ||
            (nl > pl && name[nl - pl - 1] == '.' && !memcmp(name + nl - pl, pat, pl)))
            return rs->dom_idx[k];
    }
    return INT_MAX;
}

/* Analizza un pacchetto DNS (query o risposta). Ritorna l'indice della regola di dominio
 * che combacia (o INT_MAX). Se e' una risposta, impara gli IP A. */
static int dns_inspect(const ruleset_t *rs, const struct pbuf *p, int dns_off)
{
    if (p->tot_len <= dns_off + 12) return INT_MAX;
    int len = p->tot_len - dns_off; if (len > 700) len = 700;
    uint8_t *b = malloc(len + 300);
    if (!b) return INT_MAX;
    char *name = (char *)b + len;                    /* 256 byte di appoggio */
    int best = INT_MAX;
    if (pbuf_copy_partial(p, b, len, dns_off) != len) goto out;

    int flags = (b[2] << 8) | b[3], qd = (b[4] << 8) | b[5], an = (b[6] << 8) | b[7];
    if (qd < 1) goto out;
    int off = 12, nxt;
    if (dns_name(b, len, off, name, 255, &nxt) < 0) goto out;
    best = domain_match(rs, name);
    off = nxt + 4;
    if (!(flags & 0x8000) || an == 0) goto out;      /* non e' una risposta */

    uint32_t ips[16], ttls[16]; int nip = 0;
    for (int i = 0; i < an && off < len; i++) {
        if (dns_name(b, len, off, name, 255, &nxt) < 0) break;
        off = nxt;
        if (off + 10 > len) break;
        int type = (b[off] << 8) | b[off + 1];
        uint32_t ttl = ((uint32_t)b[off + 4] << 24) | (b[off + 5] << 16) | (b[off + 6] << 8) | b[off + 7];
        int rdlen = (b[off + 8] << 8) | b[off + 9];
        off += 10;
        if (off + rdlen > len) break;
        if (type == 5) {                             /* CNAME: il bersaglio puo' essere nel dominio */
            int n2;
            if (dns_name(b, len, off, name, 255, &n2) == 0) {
                int m = domain_match(rs, name);
                if (m < best) best = m;
            }
        } else if (type == 1 && rdlen == 4 && nip < 16) {
            ips[nip] = ((uint32_t)b[off] << 24) | (b[off + 1] << 16) | (b[off + 2] << 8) | b[off + 3];
            ttls[nip++] = ttl;
        }
        off += rdlen;
    }
    if (best != INT_MAX) {
        uint32_t now = (uint32_t)(esp_timer_get_time() / 1000000);
        for (int i = 0; i < nip; i++) dyn_insert(ips[i], best, rs->gen, now, ttls[i]);
    }
out:
    free(b);
    return best;
}

/* ---------------------------------------------------------------- decisione per pacchetto */
bool filter_drop(const struct pbuf *p)
{
    ruleset_t *rs = s_rs;
    if (!rs || !s_enabled) return false;

    uint8_t h[80];
    int got = p->tot_len < (int)sizeof h ? p->tot_len : (int)sizeof h;
    if (got < 14 || pbuf_copy_partial(p, h, got, 0) != got) return false;

    int etype = (h[12] << 8) | h[13];
    bool is_ip4 = (etype == 0x0800 && got >= 34);
    uint32_t src = 0, dst = 0; uint8_t proto = 0; uint16_t sport = 0, dport = 0; bool ports = false;
    int l4 = 0;
    if (is_ip4) {
        int ihl = (h[14] & 0x0F) * 4;
        proto = h[23];
        src = ((uint32_t)h[26] << 24) | (h[27] << 16) | (h[28] << 8) | h[29];
        dst = ((uint32_t)h[30] << 24) | (h[31] << 16) | (h[32] << 8) | h[33];
        l4 = 14 + ihl;
        int frag = ((h[20] & 0x1F) << 8) | h[21];
        if ((proto == PR_TCP || proto == PR_UDP) && frag == 0 && l4 + 4 <= got) {
            sport = (h[l4] << 8) | h[l4 + 1];
            dport = (h[l4 + 2] << 8) | h[l4 + 3];
            ports = true;
        }
    }

    int best = INT_MAX;
    for (int i = 0; i < rs->n; i++) {
        const rule_t *r = &rs->rules[i];
        bool m = false;
        switch (r->kind) {
        case K_IP:    m = is_ip4 && (((src & r->m) == r->a) || ((dst & r->m) == r->a)); break;
        case K_SRC:   m = is_ip4 && ((src & r->m) == r->a); break;
        case K_DST:   m = is_ip4 && ((dst & r->m) == r->a); break;
        case K_PORT:  m = ports && ((sport >= r->p1 && sport <= r->p2) || (dport >= r->p1 && dport <= r->p2)); break;
        case K_SPORT: m = ports && sport >= r->p1 && sport <= r->p2; break;
        case K_DPORT: m = ports && dport >= r->p1 && dport <= r->p2; break;
        case K_PROTO:
            if (r->p1 == PR_ARP)       m = (etype == 0x0806);
            else if (r->p1 == PR_IPV6) m = (etype == 0x86DD);
            else                       m = is_ip4 && proto == r->p1;
            break;
        default: break;                      /* K_DOMAIN: solo tramite DNS / IP appresi */
        }
        if (m) { best = i; break; }
    }

    if (rs->ndom && is_ip4 && s_dyn) {
        uint32_t now = (uint32_t)(esp_timer_get_time() / 1000000);
        int d;
        if (proto == PR_UDP && ports && (sport == 53 || dport == 53)) {
            d = dns_inspect(rs, p, l4 + 8);
            if (d < best) best = d;
        }
        d = dyn_lookup(src, rs->gen, now); if (d < best) best = d;
        d = dyn_lookup(dst, rs->gen, now); if (d < best) best = d;
    }

    bool drop;
    if (best == INT_MAX) {
        drop = rs->default_drop;
    } else {
        rs->rules[best].hits++;
        drop = rs->rules[best].drop;
    }
    if (drop) s_dropped++; else s_kept++;
    return drop;
}
