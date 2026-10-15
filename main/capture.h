#pragma once
#include "esp_netif.h"

// Cattura dei frame Ethernet che passano sull'interfaccia AP (lato smartphone) e
// streaming su USB-Serial-JTAG (la porta USB nativa del devkit) per Wireshark.
// Il formato sul filo e' descritto in capture.c; il lato PC e' tools/pcap_bridge.py.

void capture_init(void);                         // task + driver USB-Serial-JTAG
void capture_tap_netif(esp_netif_t *esp_netif);  // aggancia input/output del netif
void capture_get_stats(uint32_t *captured, uint32_t *dropped);

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
void capture_get_usb_stats(bool *connected, uint32_t *frames, uint32_t *bytes, uint32_t *short_writes);
void capture_get_ring(size_t *total, size_t *free_bytes, uint32_t *no_usb_drops);
