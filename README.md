# Sniffer WiFi — ESP32-S3 + ENC28J60

Router intermedio **con cattura del traffico** basato su ESP32-S3. Da un lato una porta **Ethernet** (modulo ENC28J60 su SPI, verso un PC con condivisione di connessione o verso un router), dall'altro un **access point Wi-Fi aperto** (`LoggerWIFI`) a cui si collega lo smartphone da analizzare. Il traffico dello smartphone esce su Internet tramite NAT e, nel frattempo, ogni frame che passa dall'AP viene copiato sulla **porta USB nativa** verso il PC, dove uno script lo trasforma in un flusso `pcap` per **Wireshark**.

```
  Internet
     |
 [router o PC con condivisione]        es. 192.168.137.1 (condivisione di Windows)
     |  cavo Ethernet (10 Mbps)
 [ENC28J60] --SPI-- [ESP32-S3]  ----- USB nativa ----> PC: pcap_bridge.py | Wireshark
                       |  NAT (NAPT) + cattura dei frame
                    AP Wi-Fi "LoggerWIFI" 192.168.4.1/24 (aperto, max 4 client)
                       |
                   smartphone (192.168.4.x)
```

- Il **pannello web** è raggiungibile sia dall'AP (`http://192.168.4.1`) sia dall'IP Ethernet.
- La **console di log** esce sulla UART; la **USB nativa** è riservata al flusso di cattura. Per avere insieme log e cattura servono due cavi USB.
- La cattura vede il traffico **dell'interfaccia AP** (smartphone ⇄ ESP) in entrambe le direzioni, non quello della porta Ethernet.

> ⚠️ **Nessuna autenticazione**: il pannello non ha password e l'AP è aperto. Usalo in ambienti controllati (vedi [Limiti](#limiti)).

## Indice

1. [Requisiti](#requisiti)
2. [Collegamenti hardware](#collegamenti-hardware)
3. [Compilazione e flash](#compilazione-e-flash)
4. [Struttura del progetto](#struttura-del-progetto)
5. [Rete: Ethernet, AP e NAT](#rete-ethernet-ap-e-nat)
6. [Pannello web](#pannello-web)
7. [Configurazione salvata (NVS)](#configurazione-salvata-nvs)
8. [Cattura e Wireshark](#cattura-e-wireshark)
9. [Filtro di cattura](#filtro-di-cattura)
10. [Problemi frequenti](#problemi-frequenti)
11. [Stato delle verifiche](#stato-delle-verifiche)
12. [Limiti](#limiti)

## Requisiti

- Scheda **ESP32-S3** con 16 MB di flash e 8 MB di PSRAM ottale (testato su N16R8).
- Modulo **ENC28J60** (SPI Ethernet).
- **ESP-IDF v5.2.8** (il driver ENC28J60 è il componente `espressif/enc28j60`, scaricato automaticamente alla prima compilazione).
- Sul PC, per la cattura: **Python 3** con `pyserial` e **Wireshark**.

## Collegamenti hardware

| ENC28J60 | ESP32-S3 | Note |
|---|---|---|
| SCK | GPIO14 | SPI2 (`SPI2_HOST`) |
| MISO (SO) | GPIO4 | |
| MOSI (SI) | GPIO5 | |
| CS | GPIO15 | |
| INT | GPIO3 | GPIO3 è un pin di *strapping*: se il boot dà problemi, sposta INT su un GPIO libero (6/7/8) in `main.c` |
| RST | GPIO9 | pilotato dal firmware a ogni avvio (reset hardware, poi 100 ms di attesa) |
| VCC | 3V3 | il modulo assorbe circa 200 mA: alimentazione robusta |
| GND | GND | comune con la scheda |

- Clock SPI a **4 MHz**: valore verificato stabile sull'hardware. Con 8 MHz, sul cablaggio provato, la lettura dei registri PHY fallisce (`wrong chip ID` anche se `revision: 6` viene letta bene). Per revisioni del chip precedenti alla B5 gli 8 MHz sono però obbligatori.
- Il firmware assegna il MAC locale `02:00:00:12:34:56` dopo l'installazione del driver (l'`init()` del driver resetta il chip e cancellerebbe quello impostato prima).
- L'ENC28J60 è solo **10 Mbps half duplex** (`working in 10Mbps / half duplex` nel log): basta per uno smartphone, ma è il limite di banda dell'intero sistema.
- Pin da evitare per altri usi: strapping (0, 3, 45, 46), USB nativa (19, 20), console UART (43, 44), flash/PSRAM ottale (26–37).

## Compilazione e flash

```bash
cd projects/sniffer_wifi
idf.py set-target esp32s3
idf.py build
idf.py -p <PORTA_UART> flash monitor
```

> ⚠️ `sdkconfig.defaults` viene letto solo quando `sdkconfig` viene rigenerato: dopo aver cambiato un'opzione **cancella `sdkconfig` e la cartella `build/`** prima di ricompilare.

Il monitor del log usa la porta **UART** (115200 baud). La cattura usa la **USB nativa**, che sul PC è un'altra porta COM: collega due cavi se vuoi entrambe.

`idf.py flash` non tocca la partizione NVS: rete, parametri dell'AP e regole del filtro sopravvivono all'aggiornamento del firmware. Un `idf.py erase-flash` fa invece un ripristino completo, impostazioni comprese.

### Impostazioni importanti (`sdkconfig.defaults`)

| Opzione | Perché |
|---|---|
| `CONFIG_ETH_USE_SPI_ETHERNET`, `CONFIG_ETH_SPI_ETHERNET_ENC28J60` | abilitano il driver Ethernet su SPI (EMAC interno disattivato) |
| `CONFIG_LWIP_IP_FORWARD`, `CONFIG_LWIP_IPV4_NAPT`, `..._NAPT_PORTMAP` | inoltro dei pacchetti e NAT: senza di essi il NAT non si attiva |
| `CONFIG_SPIRAM*` (ottale, 80 MHz) | PSRAM per il buffer di cattura e le tabelle del filtro |
| `CONFIG_PARTITION_TABLE_CUSTOM` | tabella delle partizioni personalizzata |
| `CONFIG_ESP_CONSOLE_UART_DEFAULT`, console secondaria disattivata | il log resta sulla UART e la USB nativa è libera per la cattura |
| `CONFIG_HTTPD_MAX_REQ_HDR_LEN=2048`, `CONFIG_HTTPD_MAX_URI_LEN=512` | header HTTP più lunghi: un POST da form di Chrome supera i 512 byte di default ("Header fields are too long") |
| `CONFIG_ESP_MAIN_TASK_STACK_SIZE=6144`, `CONFIG_LWIP_TCPIP_TASK_STACK_SIZE=4096` | stack dei task principali |

### Partizioni

| Nome | Tipo | Offset | Dimensione |
|---|---|---|---|
| `nvs` | data / nvs | 0x9000 | 512 KB |
| `phy_init` | data / phy | 0x89000 | 4 KB |
| `factory` | app | 0x90000 | 3 MB |
| `storage` | data / spiffs | 0x390000 | 12 MB |

## Struttura del progetto

| File | Compito |
|---|---|
| `projects/sniffer_wifi/main/main.c` | avvio, driver ENC28J60, access point, NAT, autotest radio, heartbeat nel log |
| `projects/sniffer_wifi/main/netcfg.c/.h` | configurazione di rete persistente (Ethernet DHCP/IP fisso, parametri AP) con validazione, scrittura NVS e rilettura di verifica |
| `projects/sniffer_wifi/main/webcfg.c/.h` | pannello web (porta 80): diagnostica AP, `/net`, `/filter`, `/wireshark`, ecc. |
| `projects/sniffer_wifi/main/capture.c/.h` | aggancio ai frame dell'AP, buffer circolare in PSRAM, invio su USB-Serial-JTAG |
| `projects/sniffer_wifi/main/filter.c/.h` | filtro di cattura a regole testuali, con IP appresi dal DNS |
| `tools/pcap_bridge.py` | lato PC: legge lo stream USB e lo converte in pcap |

### Sequenza di avvio

1. Inizializzazione NVS, poi lettura della configurazione di rete salvata (o dei predefiniti), scritta nel log.
2. Stack di rete, servizio ISR dei GPIO (obbligatorio per il pin INT dell'ENC28J60), reset hardware del chip, bus SPI.
3. Driver ENC28J60, MAC locale, collegamento al netif Ethernet.
4. Applicazione dell'IP Ethernet (fisso subito; con DHCP il client parte da solo all'avvio dell'interfaccia), poi avvio Ethernet.
5. Filtro di cattura (regole da NVS o predefinite) e cattura (buffer in PSRAM, driver USB).
6. Access point con SSID, canale, potenza e visibilità letti da NVS; larghezza di banda HT20; risparmio energetico Wi-Fi spento.
7. Pannello web; autotest radio dopo 4 s; poi un **heartbeat nel log ogni 10 s** con frame catturati, scartati, stato USB e statistiche del filtro.

L'autotest radio mette per un paio di secondi il Wi-Fi in modalità AP+STA, scansiona le reti vicine (le prime 12 per segnale vengono scritte nel log) e torna in solo AP: serve a verificare antenna e ricezione. In quel momento l'AP può avere un breve disturbo.

## Rete: Ethernet, AP e NAT

### Ethernet: DHCP o IP fisso

Si sceglie dalla pagina `/net` del pannello. Predefinito, con NVS vuota: **IP fisso 192.168.137.200**, maschera 255.255.255.0, gateway e DNS 192.168.137.1 (la rete della condivisione di connessione di Windows).

| Scenario | Impostazione |
|---|---|
| PC Windows con condivisione di connessione (ICS) collegato direttamente allo sniffer | IP fisso 192.168.137.200 (predefinito) oppure DHCP: ICS assegna un indirizzo della 192.168.137.x |
| Router intermedio che assegna gli indirizzi | DHCP |
| Rete con indirizzi tuoi | IP fisso con IP, maschera, gateway e DNS della tua rete (DNS vuoto = gateway) |

Pulsanti della pagina `/net`:

- **Salva e applica ora**: salva in NVS e dopo circa 0,8 s applica a caldo (ferma il client DHCP o lo avvia, imposta IP/maschera/gateway/DNS, ricalcola il NAT). Il Wi-Fi dell'AP non si interrompe.
- **Salva (vale dal prossimo riavvio)**: salva e basta; la rete attuale non cambia.
- **Salva e riavvia**: salva e riavvia lo sniffer.
- Passando a DHCP gli ultimi valori fissi restano salvati, così si può tornare indietro senza riscriverli.

> Se sei collegato via Ethernet e applichi un indirizzo diverso, la pagina smette di rispondere: riaprila al nuovo IP (con DHCP lo leggi in "Stato attuale" collegandoti al Wi-Fi `LoggerWIFI` su `http://192.168.4.1/net`). Dall'AP il pannello è sempre raggiungibile, quindi non si resta mai chiusi fuori.

**Controlli sui valori inseriti.** Il firmware rifiuta, con un messaggio, un IP non valido o non utilizzabile (0, loopback, multicast, indirizzo di rete o di broadcast), una maschera non contigua o più piccola di /30, un gateway fuori dalla rete dell'IP o uguale all'IP, un DNS non valido. Rifiuta anche qualunque rete che si **sovrapponga a 192.168.4.0/24**, la rete dell'AP: con due reti uguali il NAT non può funzionare.

### Access point

| Parametro | Valore |
|---|---|
| SSID | `LoggerWIFI` (modificabile) |
| Sicurezza | **aperto**, senza password |
| Canale | 6 (modificabile 1–13), larghezza 20 MHz (HT20) |
| Potenza | 8 dBm di default (modificabile 2–20): oltre circa 9 dBm l'AP può diventare instabile per l'alimentazione della scheda |
| Client | massimo 4 |
| Rete | 192.168.4.0/24; l'ESP è 192.168.4.1 e assegna gli indirizzi ai client (DHCP dell'AP) |

### NAT

Quando Ethernet ottiene un indirizzo (o l'AP riparte) il firmware:

1. sceglie il DNS ricevuto o configurato su Ethernet (se manca, usa `8.8.8.8`) e lo offre ai client dell'AP tramite il DHCP dell'AP;
2. imposta Ethernet come interfaccia predefinita (rotta di default);
3. attiva il NAPT sull'interfaccia AP: lo smartphone esce su Internet con l'indirizzo Ethernet dello sniffer.

Va rifatto a ogni riavvio dell'AP, perché il suo server DHCP riparte e perde l'opzione DNS: il firmware lo fa da solo. L'avviso `napt disabled on esp_netif` nel log subito prima dell'attivazione è normale.

Per verificare l'uscita su Internet dello sniffer stesso usa `/nettest`: mostra IP, gateway, DNS e interfaccia predefinita, poi prova una risoluzione DNS (`example.com`) e una connessione TCP a `1.1.1.1:80`.

## Pannello web

Porta 80, sia dall'AP sia dall'IP Ethernet. **Non c'è autenticazione.**

| Indirizzo | Funzione |
|---|---|
| `/` | diagnostica dell'AP: SSID, canale, potenza, paese, MAC, stazioni connesse, heap libero, uptime, contatori di frame di gestione e *probe request*; form "Modifica al volo" per SSID, canale, potenza e SSID nascosto (applicati subito **e salvati in NVS**); interruttori di filtro, tap di cattura e modalità promiscua |
| `/net` | rete Ethernet: stato reale, scelta DHCP / IP fisso, contenuto di NVS riletto da flash |
| `/net/reset` | cancella la configurazione di rete salvata e riavvia con i predefiniti |
| `/filter` | editor delle regole di cattura, con contatori per regola e statistiche |
| `/wireshark` | comandi da copiare per avviare lo script sul PC e stato dello stream USB |
| `/nettest` | prova di DNS e TCP dello sniffer verso Internet |
| `/toggle?tap=0\|1`, `filter=0\|1`, `promisc=0\|1` | interruttori: tap di cattura (0 = l'AP funziona senza copiare i frame, utile per diagnosi), filtro, modalità promiscua per i probe request |
| `/restart` | riavvia lo sniffer |

## Configurazione salvata (NVS)

La partizione `nvs` è da 512 KB. Lo sniffer usa due namespace:

| Namespace | Chiave | Contenuto | Predefinito |
|---|---|---|---|
| `netcfg` | `eth_mode` | 0 = DHCP, 1 = IP fisso | 1 |
| | `eth_ip` | IP fisso | 192.168.137.200 |
| | `eth_mask` | maschera | 255.255.255.0 |
| | `eth_gw` | gateway | 192.168.137.1 |
| | `eth_dns` | DNS | 192.168.137.1 |
| | `ap_ssid` | SSID dell'AP | LoggerWIFI |
| | `ap_ch` | canale 1–13 | 6 |
| | `ap_dbm` | potenza 2–20 dBm | 8 |
| | `ap_hid` | SSID nascosto 0/1 | 0 |
| `sniffer` | `rules` | testo del filtro di cattura (fino a 64 KB) | regole predefinite |

- **Verifica a ogni salvataggio**: dopo la scrittura e il commit il firmware rilegge da NVS e confronta con quanto scritto; se non coincide, la pagina mostra un errore e il valore non viene considerato salvato. Nel log compare `[NETCFG] ... salvato in NVS (verificato)`.
- **All'avvio** il log dice `[ETH] da NVS: IP fisso` (o `DHCP`) e `[AP] da NVS: ...`, oppure `nessuna configurazione in NVS: predefiniti`. Se i valori in NVS non sono validi si torna ai predefiniti, con un avviso nel log.
- La pagina `/net` elenca le chiavi come sono **in flash in quel momento**, non quelle in RAM: è il modo più rapido per controllare che il salvataggio sia andato a buon fine.

## Cattura e Wireshark

### Cosa viene catturato

Il firmware si aggancia all'ingresso e all'uscita dell'interfaccia dell'AP: ogni frame Ethernet scambiato con lo smartphone viene (se il filtro lo lascia passare) copiato in un **buffer circolare da 4 MB in PSRAM** (48 KB in RAM interna se la PSRAM non c'è). Un task lo svuota verso la **USB-Serial-JTAG** (buffer di trasmissione da 8 KB). Il traffico che non passa dall'AP non è catturato.

### Formato sul filo

Un record per frame, little endian:

```
A5 5A | caplen u16 | origlen u16 | dir u8 | rsv u8 | ts_sec u32 | ts_usec u32 | dati[caplen]
dir: 0 = dallo smartphone verso l'ESP (ingresso AP)   1 = dall'ESP verso lo smartphone (uscita AP)
```

Il marcatore `A5 5A` permette allo script di risincronizzarsi se perde dei byte. Il timestamp parte dall'avvio dell'ESP: lo script lo ancora all'orologio del PC al primo frame ricevuto.

### Avviare Wireshark

Lo script gira **sul PC**; la pagina `/wireshark` del pannello dà i comandi pronti da copiare (con il campo per la porta COM). Prima volta: `pip install pyserial`. I comandi si lanciano dalla cartella `tools`.

| Caso | Comando |
|---|---|
| Wireshark in diretta, **cmd** di Windows | `python pcap_bridge.py COM7 \| "C:\Program Files\Wireshark\Wireshark.exe" -k -i -` |
| Wireshark in diretta, **PowerShell** | `cmd /c 'python pcap_bridge.py COM7 \| "C:\Program Files\Wireshark\Wireshark.exe" -k -i -'` (la pipe diretta di PowerShell rovina i dati binari: serve `cmd /c`) |
| Solo salvataggio su file | `python pcap_bridge.py COM7 --out cattura.pcap` (si ferma con Ctrl+C) |
| Linux / macOS | `python3 pcap_bridge.py /dev/ttyACM0 \| wireshark -k -i -` |

- `COM7` è un esempio: usa la porta che in Gestione dispositivi compare come **USB JTAG/serial debug unit** (la USB nativa, non la UART).
- Una porta COM può essere aperta da un solo programma: chiudi eventuali monitor seriali sulla USB nativa.
- Lo script scrive l'intestazione pcap (microsecondi, Ethernet) e poi un record per frame; se Wireshark viene chiuso termina e stampa il numero di frame scritti.

### Stato dello stream

La pagina `/wireshark` e l'heartbeat nel log mostrano: USB connessa (sì/no), frame e byte inviati al PC, frame catturati dall'avvio, scritture incomplete, spazio libero del buffer e frame scartati perché non c'era nessun PC collegato. I frame vengono scartati (non accumulati) quando la USB non è collegata o lo script non è in esecuzione. Il filtro di cattura agisce **prima** del buffer, quindi i frame esclusi non occupano né memoria né banda USB.

### Vedere il contenuto cifrato (TLS) sul proprio telefono

Lo sniffer, da solo, non può leggere il contenuto del traffico `https://`: cattura i pacchetti cifrati. Per leggerli serve far passare il traffico del telefono da un programma sul PC che lo decifra e lo ricifra ([mitmproxy](https://mitmproxy.org)), con un certificato a cui il telefono si fida. Lo sniffer continua a registrare i pacchetti per Wireshark; mitmproxy mostra il contenuto decifrato in una sua finestra.

> Usa queste procedure solo sui **tuoi** dispositivi, con le **tue** app o app che hai il diritto di analizzare, e solo sul tuo traffico. Il certificato installato permette di leggere tutto ciò che passa: toglilo a fine prova. Molte app (banche, pagamenti, streaming) rifiutano di funzionare con un certificato aggiunto o con il root.

**Preparazione comune (PC)**

1. `pip install mitmproxy`, poi avvia `mitmweb` (porta `8080`).
2. Il PC è sulla stessa rete dello sniffer lato Ethernet (con la condivisione di Windows `192.168.137.1`). Il telefono, collegato a `LoggerWIFI`, lo raggiunge attraverso il NAT. Consenti la porta 8080 nel firewall del PC (rete "privata").
3. Sul telefono: Wi-Fi → `LoggerWIFI` → Proxy "Manuale" → host `192.168.137.1` (o l'IP del PC), porta `8080`.
4. Con il proxy attivo apri `http://mitm.it` nel browser del telefono e scarica il certificato per Android.

**Telefono NON rooted**

1. Installa il certificato come **certificato CA utente** (Impostazioni → Sicurezza → Crittografia e credenziali → Installa un certificato → Certificato CA; il percorso cambia da marca a marca).
2. Da Android 7 le app **ignorano** i certificati utente per impostazione predefinita: funzionano il browser e le app che li accettano.
3. Per le app tue basta aggiungere in `res/xml/network_security_config.xml` la fiducia nei certificati utente (`<certificates src="user"/>`), solo nella build di debug.
4. Per app di terzi, `apk-mitm` (Node.js) aggiunge la configurazione di rete e prova a togliere il *certificate pinning*; l'app modificata ha però una firma diversa (niente aggiornamenti dallo store, alcune app non partono).
5. Alternativa: emulatore Android del PC (immagine "Google APIs", non "Play Store"), dove puoi avere il root e il certificato di sistema.

**Telefono rooted (Magisk)**

1. Con il root il certificato si installa come **certificato di sistema**, accettato da tutte le app. Fai prima l'installazione utente come sopra.
2. **Android 13 e precedenti**: copia il certificato in `/system/etc/security/cacerts/` con nome `<hash>.0` (hash da `openssl x509 -inform PEM -subject_hash_old -in mitmproxy-ca-cert.pem -noout`), di solito con un modulo Magisk "systemless" (tipo "Always Trust User Certificates").
3. **Android 14 e successivi**: i certificati di sistema stanno nel modulo Conscrypt (`/apex/com.android.conscrypt/cacerts`): servono moduli Magisk aggiornati; verifica che supportino la tua versione.
4. **App con certificate pinning**: avvia `frida-server` sul telefono (stessa versione di `frida` sul PC, via `adb`) e usa `objection -g nome.pacchetto explore` poi `android sslpinning disable`, oppure uno script "universal Android SSL pinning bypass". Il pinning in codice nativo (alcune app Flutter) richiede script specifici.
5. **App che ignorano il proxy** del Wi-Fi: con il root puoi forzare il traffico con regole `iptables` (`REDIRECT` delle porte 80/443 verso il PC) e avviare mitmproxy in modalità trasparente (`--mode transparent` su Linux) oppure `--mode wireguard`, che funziona anche senza root sul telefono con l'app WireGuard.

**Leggere il risultato anche in Wireshark (facoltativo).** Avviando mitmproxy con `SSLKEYLOGFILE=chiavi.log`, le chiavi di sessione TLS finiscono in quel file; in Wireshark: Modifica → Preferenze → Protocolli → TLS → *(Pre)-Master-Secret log filename*. La cattura dello sniffer relativa alla parte telefono ⇄ PC si decifra.

| Sintomo | Probabile causa |
|---|---|
| "Connessione non privata" nel browser | certificato non installato come CA, o data/ora del telefono errata |
| Il browser funziona, l'app no | l'app non accetta certificati utente (Android 7+) oppure fa il pinning |
| Nessuna richiesta in mitmproxy | proxy non impostato sul Wi-Fi, firewall sulla porta 8080, IP del PC sbagliato, o l'app ignora il proxy |
| Dopo la prova il telefono non naviga | togli il proxy dal Wi-Fi e rimuovi il certificato (Crittografia e credenziali → Credenziali utente) |

## Filtro di cattura

Per non inondare Wireshark di traffico inutile (ad esempio quello continuo di Google su Android) le regole si scrivono come testo nella pagina `/filter`, si salvano in NVS e si applicano subito. Una regola per riga, `#` inizia un commento, **vince la prima regola che combacia**; se nessuna combacia, vale `default`.

| Regola | Significato |
|---|---|
| `default keep\|drop` | cosa fare se nessuna regola combacia |
| `snaplen N` | byte catturati per frame (64–1600) |
| `drop\|keep ip A.B.C.D ...` | IPv4 sorgente **o** destinazione; accetta anche CIDR `A.B.C.D/N` e più valori sulla stessa riga |
| `drop\|keep src ...` / `dst ...` | solo sorgente / solo destinazione |
| `drop\|keep port N\|N-M ...` | porta TCP/UDP sorgente o destinazione (anche `sport`, `dport`) |
| `drop\|keep proto tcp udp icmp arp ipv6` | per protocollo |
| `drop\|keep domain nome ...` | per nome di dominio, come suffisso: `google.com` vale anche per `www.google.com` |

```
# esempi
default keep
snaplen 96                       # solo le intestazioni
drop domain google.com youtube.com
drop port 853                    # DNS su TLS
drop proto arp
# per catturare solo un server:
#   default drop
#   keep ip 93.184.216.34
```

**Come funzionano i domini.** Un frame non contiene il nome del sito, solo l'IP. Il filtro quindi **ascolta le risposte DNS** che passano dall'AP (porta 53) e, per ogni nome che combacia con una regola di dominio, memorizza gli indirizzi IP restituiti (compresi quelli raggiunti tramite CNAME). I frame verso quegli IP seguono poi la regola, per tutta la durata della risposta DNS (limitata tra 5 minuti e 1 ora). La tabella degli IP appresi ha 8192 voci. Anche le query DNS stesse vengono filtrate per nome.

> Un dominio funziona solo se il suo DNS passa dall'AP *dopo* l'applicazione della regola. Per i grandi servizi (Google) il filtro predefinito aggiunge anche gli intervalli IP principali, così non dipende dal DNS.

- Fino a 4096 regole, testo massimo 64 KB. Le tabelle stanno in PSRAM.
- Il testo predefinito scarta i domini e gli intervalli IP di Google (Android) e tiene tutto il resto, con snaplen 1600.
- La pagina `/filter` mostra per ogni regola quante volte ha combaciato, i frame scartati/tenuti, gli IP appresi dal DNS, la PSRAM libera e lo stato del buffer di cattura. L'interruttore "filtro off" sulla pagina principale lo esclude senza cancellare le regole.
- "Salva e applica" riporta gli errori di sintassi riga per riga; le righe sbagliate vengono segnalate, non applicate silenziosamente.

## Problemi frequenti

| Sintomo | Cosa controllare |
|---|---|
| `esp_eth_driver_install` fallita, `wrong chip ID` | guarda la riga `enc28j60: revision: N` subito prima. **0 o 255**: il chip non risponde (MISO/CS errati, alimentazione, GND, RST). **5 o 6 (B5/B7)** ma ancora "wrong chip ID": l'SPI di base funziona ma la lettura dei registri PHY dà valori sbagliati (MISO instabile, saldatura fredda, GND debole, clock troppo alto): verifica che il clock SPI in `main.c` sia a 4 MHz e fai un ciclo completo di alimentazione |
| `[ETH] Link Down`, nessun IP | cavo e porta del PC/router; il link impiega un paio di secondi a salire dopo il boot |
| Con DHCP non arriva nessun IP | sul PC Windows la condivisione di connessione deve essere attiva sull'adattatore giusto; su un router verifica che il server DHCP sia attivo. Intanto AP e pannello restano usabili (`192.168.4.1`) |
| "Header fields are too long" salvando da una pagina | firmware compilato con un `sdkconfig` vecchio: cancella `sdkconfig` e `build/` e ricompila |
| La pagina smette di rispondere dopo aver cambiato IP | atteso: riaprila al nuovo indirizzo o dall'AP su `192.168.4.1/net` |
| La rete Ethernet è 192.168.4.x | si sovrappone all'AP, il NAT non funziona: cambia la rete del router o usa un IP fisso su un'altra rete |
| Lo smartphone si connette ma non naviga | apri `/nettest`: se DNS o TCP falliscono il problema è a monte (gateway, condivisione). Nel log cerca `[NAT] NAPT attivo` |
| AP poco visibile o instabile | potenza troppo alta per l'alimentazione (tieni `ap_dbm` sotto circa 9) e alimentazione/cavo USB di qualità |
| Wireshark non riceve nulla | `/wireshark` deve dire USB connessa sì e frame in aumento. Controlla la porta COM (USB nativa, non UART), che nessun altro programma la tenga aperta, `pyserial` installato e, in PowerShell, l'uso di `cmd /c` |
| Nessun frame catturato ma lo smartphone naviga | tap spento (`/toggle?tap=1` per riaccenderlo) o filtro che scarta tutto (guarda i contatori in `/filter`) |
| Cattura che perde frame | la USB nativa è full speed (12 Mbit/s) e il buffer in PSRAM è di 4 MB: con traffico intenso usa il filtro o riduci lo snaplen |

## Stato delle verifiche

- Compilato con ESP-IDF v5.2.8 e provato su scheda reale (ESP32-S3, ENC28J60 rev. B7, 16 MB di flash, 8 MB di PSRAM).
- **Provato sull'hardware** (log seriale): primo avvio con NVS vuota e predefiniti; salvataggio verificato per rilettura con tutti e tre i pulsanti di `/net`; applicazione a caldo con IP fisso; passaggio a DHCP a caldo; riavvio con IP fisso e con DHCP, con la configurazione riletta da NVS; salvataggio e rilettura dei parametri dell'AP; NAT che si riattiva dopo ogni cambio di IP.
- La logica di validazione e di scrittura/lettura NVS è provata anche su PC con una NVS simulata.
- **Da verificare**: un IP fisso diverso da 192.168.137.200 (per esempio dietro un router reale); parametri AP diversi dai predefiniti dopo un riavvio; il ciclo completo di cattura con Wireshark su traffico reale; la banda sostenibile sulla USB nativa con traffico intenso.

## Limiti

- **Nessuna autenticazione**: il pannello non ha password e l'AP è aperto, quindi chiunque si colleghi a `LoggerWIFI` (o sia sulla rete Ethernet) può cambiare IP, filtro e riavviare lo sniffer. Anche gli interruttori e il riavvio sono richieste GET.
- **Cosa si vede in Wireshark.** La cattura copia solo i frame scambiati tra lo smartphone e lo sniffer sul Wi-Fi. Il traffico TLS è cifrato: restano visibili indirizzi IP e porte, il nome del sito (se il DNS è in chiaro, oppure nell'handshake TLS con il campo SNI; non con ECH), dimensioni e tempi, e per intero il traffico non cifrato (HTTP, DNS in chiaro, ARP, DHCP). Per leggere il contenuto sul proprio telefono vedi [Vedere il contenuto cifrato (TLS)](#vedere-il-contenuto-cifrato-tls-sul-proprio-telefono).
- **Velocità e protocolli.** Banda limitata dall'ENC28J60 (10 Mbps half duplex) e dal NAT software; massimo 4 client sull'AP. Il NAT instrada solo **IPv4**: il traffico IPv6 dello smartphone non esce verso Internet, ma app e siti ripiegano da soli su IPv4. In Wireshark compare comunque anche il traffico non IPv4 (ARP, IPv6 locale).
- **Filtro per dominio e DNS.** Le regole `domain` non scattano se il telefono usa il **DNS cifrato** (DoT sulla porta 853, DoH dentro HTTPS; su Android con "DNS privato" attivo — controlla il contatore "IP appresi dal DNS" in `/filter`) oppure se l'app ha l'indirizzo in **cache** (risolto prima dell'attivazione della regola). In alternativa usa regole per IP o `drop port 853`.
- Gli indirizzi dell'AP (192.168.4.0/24) non sono configurabili da pannello: la rete Ethernet deve evitarli.
