idf_component_register(SRCS "main.c" "capture.c" "webcfg.c" "filter.c" "netcfg.c"
                    INCLUDE_DIRS "."
                    REQUIRES esp_eth esp_wifi nvs_flash driver lwip esp_netif esp_timer esp_http_server esp_ringbuf heap)
