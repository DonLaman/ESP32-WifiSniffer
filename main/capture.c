#include <stdlib.h>
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "freertos/ringbuf.h"
#include "esp_log.h"
#include "esp_timer.h"
#include "esp_heap_caps.h"
#include "esp_netif.h"
#include "esp_netif_net_stack.h"
#include "driver/usb_serial_jtag.h"
#include "lwip/netif.h"
#include "lwip/pbuf.h"
#include "lwip/tcpip.h"
#include "capture.h"
#include "filter.h"

static const char *TAG = "CAPTURE";

#define SNAPLEN_MAX    1600   // limite assoluto (lo snaplen effettivo viene dal filtro)
#define RING_BYTES     (4 * 1024 * 1024)   // buffer circolare in PSRAM (assorbe le raffiche)
#define RING_FALLBACK  (48 * 1024)         // se non c'e' PSRAM
#define USB_WRITE_MS   20

// Record sul filo (little endian):
//   A5 5A | caplen u16 | origlen u16 | dir u8 | rsv u8 | ts_sec u32 | ts_usec u32 | dati[caplen]
// dir: 0 = dallo smartphone verso l'ESP (RX dell'AP), 1 = dall'ESP verso lo smartphone (TX dell'AP)
typedef struct __attribute__((packed)) {
    uint8_t  magic[2];
    uint16_t caplen;
    uint16_t origlen;
    uint8_t  dir;
    uint8_t  rsv;
    uint32_t ts_sec;
    uint32_t ts_usec;
} cap_hdr_t;

static RingbufHandle_t s_rb;
static size_t s_rb_size;
static volatile uint32_t s_captured, s_dropped, s_nousb;
static volatile uint32_t s_written_frames, s_written_bytes, s_write_short;

volatile int g_capture_tap_on = 1;   // 0 = pass-through puro (diagnostica)
static netif_input_fn      s_orig_input;
static netif_linkoutput_fn s_orig_linkoutput;

static void enqueue_frame(const struct pbuf *p, uint8_t dir)
{
    if (!s_rb) return;
    if (filter_drop(p)) return;                       // scartato dalle regole di testo

    uint16_t snap = filter_snaplen();
    if (snap > SNAPLEN_MAX) snap = SNAPLEN_MAX;
    uint16_t caplen = p->tot_len > snap ? snap : p->tot_len;

    void *slot = NULL;
    if (xRingbufferSendAcquire(s_rb, &slot, sizeof(cap_hdr_t) + caplen, 0) != pdTRUE || !slot) {
        s_dropped++;                                  // buffer pieno: si scarta
        return;
    }
    cap_hdr_t *rec = (cap_hdr_t *)slot;
    int64_t t = esp_timer_get_time();
    rec->magic[0] = 0xA5;
    rec->magic[1] = 0x5A;
    rec->caplen   = caplen;
    rec->origlen  = p->tot_len;
    rec->dir      = dir;
    rec->rsv      = 0;
    rec->ts_sec   = (uint32_t)(t / 1000000);
    rec->ts_usec  = (uint32_t)(t % 1000000);
    pbuf_copy_partial(p, (uint8_t *)slot + sizeof(cap_hdr_t), caplen, 0);
    xRingbufferSendComplete(s_rb, slot);
    s_captured++;
}

// Frame ricevuti dall'AP (smartphone -> ESP), prima che lwIP li elabori
static err_t tap_input(struct pbuf *p, struct netif *inp)
{
    if (g_capture_tap_on) enqueue_frame(p, 0);
    return s_orig_input(p, inp);
}

// Frame trasmessi dall'AP (ESP -> smartphone)
static err_t tap_linkoutput(struct netif *netif, struct pbuf *p)
{
    if (g_capture_tap_on) enqueue_frame(p, 1);
    return s_orig_linkoutput(netif, p);
}

static void capture_task(void *arg)
{
    for (;;) {
        size_t sz = 0;
        void *item = xRingbufferReceive(s_rb, &sz, pdMS_TO_TICKS(200));
        if (!item) continue;
        if (usb_serial_jtag_is_connected()) {
            int w = usb_serial_jtag_write_bytes(item, sz, pdMS_TO_TICKS(USB_WRITE_MS));
            if (w == (int)sz) { s_written_frames++; s_written_bytes += w; }
            else { s_write_short++; if (w > 0) s_written_bytes += w; }
        } else {
            s_nousb++;                                // nessun PC collegato: scarto
        }
        vRingbufferReturnItem(s_rb, item);
    }
}

void capture_init(void)
{
    usb_serial_jtag_driver_config_t cfg = USB_SERIAL_JTAG_DRIVER_CONFIG_DEFAULT();
    cfg.tx_buffer_size = 8192;
    ESP_ERROR_CHECK(usb_serial_jtag_driver_install(&cfg));

    s_rb_size = RING_BYTES;
    {
        StaticRingbuffer_t *sr = heap_caps_calloc(1, sizeof(StaticRingbuffer_t), MALLOC_CAP_INTERNAL | MALLOC_CAP_8BIT);
        uint8_t *st = heap_caps_malloc(s_rb_size, MALLOC_CAP_SPIRAM | MALLOC_CAP_8BIT);
        if (sr && st) s_rb = xRingbufferCreateStatic(s_rb_size, RINGBUF_TYPE_NOSPLIT, st, sr);
        if (!s_rb) { free(sr); free(st); }
    }
    if (!s_rb) {
        ESP_LOGW(TAG, "PSRAM non disponibile per il buffer di cattura: uso %d KB di RAM interna", RING_FALLBACK / 1024);
        s_rb_size = RING_FALLBACK;
        s_rb = xRingbufferCreate(s_rb_size, RINGBUF_TYPE_NOSPLIT);
    }
    if (!s_rb) {
        ESP_LOGE(TAG, "buffer di cattura non creato");
        return;
    }
    xTaskCreate(capture_task, "capture", 4096, NULL, 5, NULL);
    ESP_LOGI(TAG, "Cattura pronta: buffer %u KB, stream pcap su USB nativa (tools/pcap_bridge.py)",
             (unsigned)(s_rb_size / 1024));
}

void capture_tap_netif(esp_netif_t *esp_netif)
{
    struct netif *n = esp_netif_get_netif_impl(esp_netif);
    if (!n) {
        ESP_LOGE(TAG, "netif lwIP non disponibile, cattura non agganciata");
        return;
    }
    // Ad ogni avvio dell'AP esp_netif richiama netif_add() e ripristina input/linkoutput
    // originali: l'aggancio va quindi rifatto tutte le volte che non e' piu' al suo posto.
    if (n->input == tap_input && n->linkoutput == tap_linkoutput) {
        return;
    }
    if (n->input != tap_input)           s_orig_input      = n->input;
    if (n->linkoutput != tap_linkoutput) s_orig_linkoutput = n->linkoutput;
    n->input      = tap_input;
    n->linkoutput = tap_linkoutput;
    ESP_LOGI(TAG, "Tap agganciato all'interfaccia AP (RX e TX)");
}

void capture_get_stats(uint32_t *captured, uint32_t *dropped)
{
    if (captured) *captured = s_captured;
    if (dropped)  *dropped  = s_dropped;
}

void capture_get_usb_stats(bool *connected, uint32_t *frames, uint32_t *bytes, uint32_t *short_writes)
{
    if (connected)    *connected    = usb_serial_jtag_is_connected();
    if (frames)       *frames       = s_written_frames;
    if (bytes)        *bytes        = s_written_bytes;
    if (short_writes) *short_writes = s_write_short;
}

void capture_get_ring(size_t *total, size_t *free_bytes, uint32_t *no_usb_drops)
{
    if (total)        *total = s_rb_size;
    if (free_bytes)   *free_bytes = s_rb ? xRingbufferGetCurFreeSize(s_rb) : 0;
    if (no_usb_drops) *no_usb_drops = s_nousb;
}
