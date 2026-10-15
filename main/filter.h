#pragma once
/* Filtro di cattura configurabile a runtime (testo), con tabelle in PSRAM.
 *
 * Sintassi (una regola per riga, '#' = commento, prima regola che combacia vince):
 *   default keep|drop            cosa fare se nessuna regola combacia
 *   snaplen N                    byte catturati per frame (64..1600)
 *   drop|keep ip     A [B ...]   IPv4 sorgente O destinazione (a.b.c.d oppure CIDR a.b.c.d/n)
 *   drop|keep src    ...         solo sorgente
 *   drop|keep dst    ...         solo destinazione
 *   drop|keep port   N|N-M ...   porta TCP/UDP sorgente o destinazione
 *   drop|keep sport/dport ...    solo porta sorgente / destinazione
 *   drop|keep proto  tcp|udp|icmp|arp|ipv6 ...
 *   drop|keep domain nome ...    suffisso di dominio (google.com vale anche per www.google.com).
 *                                Gli IP vengono appresi dalle risposte DNS che passano dall'AP.
 */
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"

struct pbuf;

#define FILTER_MAX_TEXT 65536       /* NVS da 512 KB (partitions.csv): un blob da 64 KB entra con margine */

typedef struct {
    bool     enabled;
    int      nrules;
    int      ndomains;
    bool     default_drop;
    uint16_t snaplen;
    uint32_t learned_ips;           /* IP appresi dai DNS (cumulativo) */
    uint32_t dropped;
    uint32_t kept;
} filter_stats_t;

esp_err_t   filter_init(void);                         /* carica da NVS (o predefinito) */
int         filter_apply_text(const char *text, bool save, char *report, size_t report_len);
                                                       /* ritorna n. errori di sintassi */
const char *filter_get_text(void);
const char *filter_default_text(void);
bool        filter_drop(const struct pbuf *p);         /* true = non catturare */
uint16_t    filter_snaplen(void);
void        filter_set_enabled(bool on);
bool        filter_is_enabled(void);
void        filter_get_stats(filter_stats_t *s);
int         filter_rule_count(void);
bool        filter_rule_info(int idx, int *line, uint32_t *hits);
bool        filter_rule_desc(int idx, char *out, size_t len);   /* es. "drop domain google.com" */
void       *psram_alloc(size_t n);                     /* PSRAM se presente, altrimenti heap */
