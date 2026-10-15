#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_log.h"
#include "esp_system.h"
#include "esp_chip_info.h"
#include "esp_flash.h"
#include "esp_netif.h"
#include "esp_event.h"
#include "esp_eth.h"
#include "esp_wifi.h"
#include "nvs_flash.h"
#include "driver/spi_master.h"
#include "driver/gpio.h"
#include "esp_rom_sys.h"
#include "esp_eth_enc28j60.h"
#include "esp_mac.h"
#include "esp_netif_net_stack.h"
#include "capture.h"
#include "webcfg.h"
#include "filter.h"
#include "netcfg.h"

static const char *TAG = "SNIFFER_WIFI";

// --- Configurazione Pin ENC28J60 ---
// NOTA: i pin strapping dell'ESP32-S3 sono GPIO0, 3, 45, 46 (non 11/12/13).
// GPIO3 (INT) e' strapping: se dai problemi al boot, sposta INT su un GPIO libero (es. 6/7/8).
#define PIN_ETH_SCK    14
#define PIN_ETH_MISO   4
#define PIN_ETH_MOSI   5
#define PIN_ETH_CS     15
#define PIN_ETH_INT    3
#define PIN_ETH_RST    9

// --- Rete Ethernet (DHCP / IP fisso) e parametri AP: vedi netcfg.c ---
// Si scelgono dalla pagina web /net e restano salvati in NVS (namespace "netcfg").
// Predefiniti, se NVS e' vuota: IP fisso 192.168.137.200 (ICS di Windows), AP "LoggerWIFI" ch 6.

// --- Configurazione Wi-Fi AP ---
#define AP_MAX_STA_CONN 4
static ap_cfg_t s_apc;   // SSID/canale/potenza/nascosto caricati da NVS

static void eth_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
static void got_ip_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);
static void ap_sta_ip_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);

static esp_netif_t *s_eth_netif = NULL;
static esp_netif_t *s_ap_netif  = NULL;
void net_nat_apply(void);
#define nat_apply net_nat_apply
static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data);

// Autotest radio: l'ESP32 scansiona le reti vicine e le scrive nel log.
// Se vede il tuo router con un buon RSSI, la ricezione e l'antenna funzionano.
static void wifi_selftest_task(void *arg)
{
    vTaskDelay(pdMS_TO_TICKS(4000));
    ESP_LOGI(TAG, "[SELFTEST] scansione Wi-Fi 2.4 GHz in corso...");
    esp_wifi_set_mode(WIFI_MODE_APSTA);
    wifi_scan_config_t sc = { .show_hidden = true, .scan_type = WIFI_SCAN_TYPE_ACTIVE };
    esp_err_t r = esp_wifi_scan_start(&sc, true);
    if (r != ESP_OK) {
        ESP_LOGE(TAG, "[SELFTEST] scan fallita: %s", esp_err_to_name(r));
    } else {
        uint16_t total = 0;
        esp_wifi_scan_get_ap_num(&total);
        uint16_t n = total > 12 ? 12 : total;
        wifi_ap_record_t *recs = calloc(n ? n : 1, sizeof(wifi_ap_record_t));
        if (recs && esp_wifi_scan_get_ap_records(&n, recs) == ESP_OK) {
            ESP_LOGI(TAG, "[SELFTEST] reti viste: %u (prime %u per segnale)", total, n);
            for (int i = 0; i < n; i++) {
                ESP_LOGI(TAG, "[SELFTEST]  ch%-2d %4d dBm  %s", recs[i].primary, recs[i].rssi,
                         (char *)recs[i].ssid);
            }
        }
        free(recs);
    }
    esp_wifi_set_mode(WIFI_MODE_AP);
    uint8_t ch = 0; wifi_second_chan_t sec;
    esp_wifi_get_channel(&ch, &sec);
    ESP_LOGI(TAG, "[SELFTEST] fine. AP \"%s\" torna attivo sul canale %u", s_apc.ssid, ch);
    vTaskDelete(NULL);
}

void app_main(void)
{
    // Inizializza NVS (necessario per Wi-Fi)
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK(ret);

    // Configurazione di rete salvata (Ethernet DHCP/fisso + AP), da NVS o predefinita
    netcfg_load();
    netcfg_ap_get(&s_apc);

    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "SNIFFER WIFI - Step 2: ENC28J60 + AP + NAT");
    ESP_LOGI(TAG, "========================================");

    esp_chip_info_t chip_info;
    esp_chip_info(&chip_info);
    uint32_t flash_size = 0;
    esp_flash_get_size(NULL, &flash_size);
    ESP_LOGI(TAG, "Chip: ESP32-S3, %d core, rev %d, flash %lu MB",
             chip_info.cores, chip_info.revision,
             (unsigned long)(flash_size / (1024 * 1024)));

    // 1. Stack di rete
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    // 1b. Servizio ISR GPIO: OBBLIGATORIO per il driver ENC28J60 (usa gpio_isr_handler_add
    //     sul pin INT). Senza, nessun interrupt arriva e RX/link non funzionano.
    ESP_ERROR_CHECK(gpio_install_isr_service(0));

    // 1c. Reset hardware ENC28J60 (RST attivo basso). Se il pin RST del modulo e'
    //     collegato e lasciato flottante/basso, il chip resta in reset.
    gpio_config_t rst_cfg = {
        .pin_bit_mask = 1ULL << PIN_ETH_RST,
        .mode = GPIO_MODE_OUTPUT,
    };
    ESP_ERROR_CHECK(gpio_config(&rst_cfg));
    gpio_set_level(PIN_ETH_RST, 0);
    esp_rom_delay_us(1000);
    gpio_set_level(PIN_ETH_RST, 1);
    vTaskDelay(pdMS_TO_TICKS(100));   // il PHY impiega ~10 ms+ a stabilizzarsi, oscillatore incluso

    // 2. SPI bus per ENC28J60
    ESP_LOGI(TAG, "Configurazione SPI per ENC28J60 (SCK=%d, MISO=%d, MOSI=%d, CS=%d, INT=%d, RST=%d)...",
             PIN_ETH_SCK, PIN_ETH_MISO, PIN_ETH_MOSI,
             PIN_ETH_CS, PIN_ETH_INT, PIN_ETH_RST);
    spi_bus_config_t buscfg = {
        .miso_io_num = PIN_ETH_MISO,
        .mosi_io_num = PIN_ETH_MOSI,
        .sclk_io_num = PIN_ETH_SCK,
        .quadwp_io_num = -1,
        .quadhd_io_num = -1,
    };
    ESP_ERROR_CHECK(spi_bus_initialize(SPI2_HOST, &buscfg, SPI_DMA_CH_AUTO));

    // 3. Netif Ethernet
    esp_netif_config_t netif_config = ESP_NETIF_DEFAULT_ETH();
    esp_netif_t *eth_netif = esp_netif_new(&netif_config);
    s_eth_netif = eth_netif;

    // 4. Driver MAC ENC28J60
    // NOTA: 8 MHz è obbligatorio per revisioni < B5 del chip
    spi_device_interface_config_t spi_devcfg = {
        .mode = 0,
        .clock_speed_hz = 4 * 1000 * 1000,  // 4 MHz: verificato stabile su hardware; a 8 MHz il PHY dell'ENC28J60 risponde 'wrong chip ID' con questo cablaggio
        .queue_size = 20,
        .spics_io_num = PIN_ETH_CS,
        .cs_ena_posttrans = enc28j60_cal_spi_cs_hold_time(4),
    };
    eth_enc28j60_config_t enc28j60_config = ETH_ENC28J60_DEFAULT_CONFIG(SPI2_HOST, &spi_devcfg);
    enc28j60_config.int_gpio_num = PIN_ETH_INT;

    // MAC address locale (l'ENC28J60 non ha un MAC bruciato). Va impostato DOPO
    // l'install del driver con ioctl: init() resetta il chip e cancellerebbe il MAC.
    uint8_t eth_mac[6] = {0x02, 0x00, 0x00, 0x12, 0x34, 0x56};

    // La config MAC NON puo' essere NULL (il driver risponde "can't set mac config to null")
    eth_mac_config_t mac_config = ETH_MAC_DEFAULT_CONFIG();
    esp_eth_mac_t *mac = esp_eth_mac_new_enc28j60(&enc28j60_config, &mac_config);
    if (mac == NULL) {
        ESP_LOGE(TAG, "Creazione MAC ENC28J60 fallita. Controlla i collegamenti SPI e l'alimentazione.");
        return;
    }

    // 6. Driver PHY
    // NOTA: ENC28J60 non ha reset PHY interno, quindi reset_gpio_num = -1
    eth_phy_config_t phy_config = ETH_PHY_DEFAULT_CONFIG();
    phy_config.autonego_timeout_ms = 0;
    phy_config.reset_gpio_num = -1;
    esp_eth_phy_t *phy = esp_eth_phy_new_enc28j60(&phy_config);

    // 7. Install driver Ethernet
    esp_eth_config_t eth_config = ETH_DEFAULT_CONFIG(mac, phy);
    esp_eth_handle_t eth_handle = NULL;
    esp_err_t inst = esp_eth_driver_install(&eth_config, &eth_handle);
    if (inst != ESP_OK) {
        ESP_LOGE(TAG, "esp_eth_driver_install fallita: %s", esp_err_to_name(inst));
        ESP_LOGE(TAG, "Chip non risponde: controlla MISO/MOSI/SCK/CS, 3.3V (serve ~200 mA), GND comune, RST.");
        ESP_LOGE(TAG, "'wrong chip ID': se sopra c'e' 'revision: 6' (B7) l'SPI base funziona ma la lettura dei registri PHY/MAC fallisce -> MISO instabile/saldatura, GND, clock troppo alto (prova 4 MHz). Se 'revision: 0/255' -> MISO/CS errati o chip non alimentato.");
        return;
    }
    ESP_ERROR_CHECK(esp_eth_ioctl(eth_handle, ETH_CMD_S_MAC_ADDR, eth_mac));
    ESP_LOGI(TAG, "MAC address: %02x:%02x:%02x:%02x:%02x:%02x",
             eth_mac[0], eth_mac[1], eth_mac[2], eth_mac[3], eth_mac[4], eth_mac[5]);
    ESP_LOGI(TAG, "ENC28J60 revisione: 0x%02x", (unsigned)emac_enc28j60_get_chip_info(mac));

    // 8. Attach driver al netif
    ESP_ERROR_CHECK(esp_netif_attach(eth_netif, esp_eth_new_netif_glue(eth_handle)));

    // 9. Event handlers Ethernet
    ESP_ERROR_CHECK(esp_event_handler_register(ETH_EVENT, ESP_EVENT_ANY_ID, &eth_event_handler, NULL));
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_ETH_GOT_IP, &got_ip_event_handler, NULL));

    // IP Ethernet: fisso o DHCP, secondo la configurazione salvata in NVS
    netcfg_eth_apply(s_eth_netif, false);
    // 10. Avvia Ethernet (DHCP partirà automaticamente se non e' fisso)
    ESP_ERROR_CHECK(esp_eth_start(eth_handle));
    ESP_LOGI(TAG, "Driver Ethernet avviato. In attesa di IP dal router...");

    // 10b. Cattura pcap verso la porta USB nativa (Wireshark)
    filter_init();     // regole di filtro (NVS o predefinite), tabelle in PSRAM
    capture_init();

    // 11. Wi-Fi AP aperto
    ESP_LOGI(TAG, "Configurazione Wi-Fi AP \"%s\" (aperto, nessuna password)...", s_apc.ssid);
    s_ap_netif = esp_netif_create_default_wifi_ap();
    ESP_ERROR_CHECK(esp_event_handler_register(IP_EVENT, IP_EVENT_AP_STAIPASSIGNED, &ap_sta_ip_handler, NULL));
    wifi_init_config_t cfg = WIFI_INIT_CONFIG_DEFAULT();
    ESP_ERROR_CHECK(esp_wifi_init(&cfg));
    ESP_ERROR_CHECK(esp_event_handler_register(WIFI_EVENT, ESP_EVENT_ANY_ID, &wifi_event_handler, NULL));
    ESP_LOGI(TAG, "[WiFi] init OK");

    wifi_config_t wifi_config = {
        .ap = {
            .channel = s_apc.channel,
            .max_connection = AP_MAX_STA_CONN,
            .authmode = WIFI_AUTH_OPEN,
            .ssid_hidden = s_apc.hidden,
            .beacon_interval = 100,
            .pmf_cfg = {
                .required = false,
            },
        },
    };

    strncpy((char *)wifi_config.ap.ssid, s_apc.ssid, sizeof wifi_config.ap.ssid - 1);
    wifi_config.ap.ssid_len = strlen((char *)wifi_config.ap.ssid);

    esp_err_t e;
    e = esp_wifi_set_mode(WIFI_MODE_AP);
    ESP_LOGI(TAG, "[WiFi] set_mode -> %s", esp_err_to_name(e));
    e = esp_wifi_set_config(WIFI_IF_AP, &wifi_config);
    ESP_LOGI(TAG, "[WiFi] set_config -> %s", esp_err_to_name(e));
    e = esp_wifi_start();
    ESP_LOGI(TAG, "[WiFi] start -> %s", esp_err_to_name(e));

    // Ritocchi opzionali DOPO l'avvio, non fatali
    e = esp_wifi_set_max_tx_power(s_apc.tx_dbm * 4);   // default 8 dBm (=32): oltre ~9 dBm l'AP puo' diventare instabile (alimentazione)
    ESP_LOGI(TAG, "[WiFi] set_max_tx_power -> %s", esp_err_to_name(e));
    e = esp_wifi_set_bandwidth(WIFI_IF_AP, WIFI_BW_HT20);   // 20 MHz: piu' robusto (il telefono si era associato a 40 MHz)
    ESP_LOGI(TAG, "[WiFi] set_bandwidth HT20 -> %s", esp_err_to_name(e));

    uint8_t pch = 0; wifi_second_chan_t sch;
    esp_wifi_get_channel(&pch, &sch);
    int8_t txp = 0; esp_wifi_get_max_tx_power(&txp);
    ESP_LOGI(TAG, "[WiFi] AP canale=%u banda=2.4GHz tx_power=%d (x0.25 dBm)", pch, txp);
    esp_wifi_set_ps(WIFI_PS_NONE);
    xTaskCreate(wifi_selftest_task, "wifi_selftest", 4096, NULL, 5, NULL);
    webcfg_start();

    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "Wi-Fi AP \"%s\" attivo (aperto).", s_apc.ssid);
    ESP_LOGI(TAG, "In attesa che lo smartphone si connetta...");
    ESP_LOGI(TAG, "========================================");

    // Loop di heartbeat
    int counter = 0;
    while (1) {
        vTaskDelay(pdMS_TO_TICKS(10000));
        counter++;
        capture_tap_netif(s_ap_netif);   // rete di sicurezza: riaggancia se l'AP e' stato riavviato
        uint32_t cap = 0, drop = 0;
        capture_get_stats(&cap, &drop);
        bool uc = false; uint32_t wf = 0, wb = 0, ws = 0;
        capture_get_usb_stats(&uc, &wf, &wb, &ws);
        filter_stats_t fs; filter_get_stats(&fs);
        ESP_LOGI(TAG, "Heartbeat #%d - frame in coda=%lu scartati=%lu | USB connessa=%d scritti=%lu (%lu B) scritture_incomplete=%lu | filtro: scartati=%lu tenuti=%lu",
                 counter, (unsigned long)cap, (unsigned long)drop, uc,
                 (unsigned long)wf, (unsigned long)wb, (unsigned long)ws, (unsigned long)fs.dropped, (unsigned long)fs.kept);
    }
}

// --- Event Handler Ethernet ---
static void eth_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    switch (event_id) {
        case ETHERNET_EVENT_CONNECTED:
            ESP_LOGI(TAG, "[ETH] Link Up");
            break;
        case ETHERNET_EVENT_DISCONNECTED:
            ESP_LOGI(TAG, "[ETH] Link Down");
            break;
        case ETHERNET_EVENT_START:
            ESP_LOGI(TAG, "[ETH] Started");
            break;
        case ETHERNET_EVENT_STOP:
            ESP_LOGI(TAG, "[ETH] Stopped");
            break;
        default:
            break;
    }
}

// Configura DNS offerto ai client + rotta di default + NAPT. Va richiamata ogni volta che
// l'AP riparte (il server DHCP dell'AP viene riavviato e perde l'opzione DNS).
void net_nat_apply(void)
{
    if (s_ap_netif == NULL || s_eth_netif == NULL) return;
    esp_netif_ip_info_t eip;
    if (esp_netif_get_ip_info(s_eth_netif, &eip) != ESP_OK || eip.ip.addr == 0) {
        ESP_LOGW(TAG, "[NAT] Ethernet senza IP, NAT rimandato");
        return;
    }
    // 1) DNS ricevuto via DHCP su Ethernet, offerto ai client dell'AP
    esp_netif_dns_info_t dns = {0};
    if (esp_netif_get_dns_info(s_eth_netif, ESP_NETIF_DNS_MAIN, &dns) != ESP_OK ||
        dns.ip.u_addr.ip4.addr == 0) {
        dns.ip.type = ESP_IPADDR_TYPE_V4;
        dns.ip.u_addr.ip4.addr = esp_ip4addr_aton("8.8.8.8");
    }
    ESP_LOGI(TAG, "[NAT] DNS offerto ai client: " IPSTR, IP2STR(&dns.ip.u_addr.ip4));

    uint8_t offer_dns = 0x02;   // OFFER_DNS
    esp_err_t d1 = esp_netif_dhcps_stop(s_ap_netif);
    esp_err_t d2 = esp_netif_set_dns_info(s_ap_netif, ESP_NETIF_DNS_MAIN, &dns);
    esp_err_t d3 = esp_netif_dhcps_option(s_ap_netif, ESP_NETIF_OP_SET, ESP_NETIF_DOMAIN_NAME_SERVER,
                                          &offer_dns, sizeof(offer_dns));
    esp_err_t d4 = esp_netif_dhcps_start(s_ap_netif);
    ESP_LOGI(TAG, "[DHCP-AP] stop=%s set_dns=%s option=%s start=%s",
             esp_err_to_name(d1), esp_err_to_name(d2), esp_err_to_name(d3), esp_err_to_name(d4));

    // 2) Rotta di default su Ethernet + NAPT sull'interfaccia AP
    esp_netif_set_default_netif(s_eth_netif);
    esp_err_t nr = esp_netif_napt_enable(s_ap_netif);
    if (nr == ESP_OK) {
        ESP_LOGI(TAG, "[NAT] NAPT attivo: il traffico di LoggerWIFI esce da Ethernet");
    } else {
        ESP_LOGE(TAG, "[NAT] NAPT non attivato: %s (serve CONFIG_LWIP_IPV4_NAPT=y)", esp_err_to_name(nr));
    }
}

static void got_ip_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    ip_event_got_ip_t *event = (ip_event_got_ip_t *)event_data;
    const esp_netif_ip_info_t *ip_info = &event->ip_info;

    ESP_LOGI(TAG, "========================================");
    ESP_LOGI(TAG, "[ETH] Got IP Address");
    ESP_LOGI(TAG, "  IP:     " IPSTR, IP2STR(&ip_info->ip));
    ESP_LOGI(TAG, "  MASK:   " IPSTR, IP2STR(&ip_info->netmask));
    ESP_LOGI(TAG, "  GW:     " IPSTR, IP2STR(&ip_info->gw));
    ESP_LOGI(TAG, "========================================");

    if (s_ap_netif == NULL) {
        ESP_LOGW(TAG, "[NAT] AP non ancora pronto, NAT non attivato");
        return;
    }

    nat_apply();
}

static void ap_sta_ip_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    ip_event_ap_staipassigned_t *e = (ip_event_ap_staipassigned_t *)event_data;
    ESP_LOGI(TAG, "[WiFi] Client %02x:%02x:%02x:%02x:%02x:%02x ha IP " IPSTR,
             e->mac[0], e->mac[1], e->mac[2], e->mac[3], e->mac[4], e->mac[5], IP2STR(&e->ip));
}

// --- Event Handler Wi-Fi ---
static void wifi_event_handler(void *arg, esp_event_base_t event_base, int32_t event_id, void *event_data)
{
    if (event_base == WIFI_EVENT) {
        switch (event_id) {
            case WIFI_EVENT_AP_START:
                ESP_LOGI(TAG, "[WiFi] AP Started");
                capture_tap_netif(s_ap_netif);
                nat_apply();   // il DHCP dell'AP riparte con l'AP: riapplica DNS/NAPT
                break;
            case WIFI_EVENT_AP_STOP:
                ESP_LOGI(TAG, "[WiFi] AP Stopped");
                break;
            case WIFI_EVENT_AP_STACONNECTED: {
                wifi_event_ap_staconnected_t *event = (wifi_event_ap_staconnected_t *)event_data;
                ESP_LOGI(TAG, "[WiFi] Client connesso - MAC: " MACSTR,
                         MAC2STR(event->mac));
                break;
            }
            case WIFI_EVENT_AP_STADISCONNECTED: {
                wifi_event_ap_stadisconnected_t *event = (wifi_event_ap_stadisconnected_t *)event_data;
                ESP_LOGI(TAG, "[WiFi] Client disconnesso - MAC: " MACSTR,
                         MAC2STR(event->mac));
                break;
            }
            default:
                break;
        }
    }
}