#pragma once
#include <stdbool.h>
#include <stdint.h>
#include <stddef.h>
#include "esp_err.h"
#include "esp_netif.h"

/*
 * Configurazione di rete persistente (NVS, namespace "netcfg").
 *
 *  - Ethernet (ENC28J60): DHCP oppure IP fisso (ip/maschera/gateway/dns).
 *  - Access point Wi-Fi: SSID, canale, potenza, nascosto.
 *
 * I valori in RAM sono quelli SALVATI: all'avvio si leggono da NVS, la pagina web /net li
 * modifica (con verifica per rilettura) e li applica subito ("a caldo") oppure al riavvio.
 */

typedef struct {
    uint8_t use_static;      /* 0 = DHCP, 1 = IP fisso */
    char    ip[16];
    char    mask[16];
    char    gw[16];
    char    dns[16];
} eth_cfg_t;

typedef struct {
    char    ssid[33];
    uint8_t channel;         /* 1..13 */
    uint8_t tx_dbm;          /* 2..20 */
    uint8_t hidden;          /* 0/1 */
} ap_cfg_t;

void netcfg_load(void);                                   /* da NVS, altrimenti predefiniti */
void netcfg_eth_get(eth_cfg_t *out);                      /* configurazione salvata */
void netcfg_ap_get(ap_cfg_t *out);

/* Valida, aggiorna la RAM, scrive in NVS e rilegge per verifica. false + err se non valido/fallito. */
bool netcfg_eth_set(const eth_cfg_t *in, char *err, size_t err_len);
bool netcfg_ap_set(const ap_cfg_t *in, char *err, size_t err_len);

/* Cio' che c'e' DAVVERO in flash (non la RAM). false = nessuna configurazione salvata. */
bool netcfg_eth_read_nvs(eth_cfg_t *out);
bool netcfg_ap_read_nvs(ap_cfg_t *out);

bool netcfg_erase(void);                                  /* cancella il namespace (poi si riavvia) */

/* Applica la configurazione Ethernet al netif. hot=false: chiamata all'avvio prima di
 * esp_eth_start (con DHCP non serve fare nulla). hot=true: a netif gia' in funzione. */
esp_err_t netcfg_eth_apply(esp_netif_t *netif, bool hot);

/* Definita in main.c: ricalcola DNS offerto ai client dell'AP, rotta di default e NAPT. */
void net_nat_apply(void);
