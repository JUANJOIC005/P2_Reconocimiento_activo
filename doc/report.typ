// =========================================================
// Práctica 2: Reconocimiento Activo
// Técnicas de Hacking — Universidad Europea de Madrid
// =========================================================

#set document(
  title: "Práctica 2: Reconocimiento Activo",
  author: "JJ",
)

#set text(font: "New Computer Modern", size: 11pt, lang: "es")

#set page(
  paper: "a4",
  margin: (top: 2.5cm, bottom: 2.5cm, left: 2.5cm, right: 2.5cm),
  numbering: "1",
  number-align: center,
)

#set heading(numbering: "1.1.")

#set par(justify: true, leading: 0.65em, first-line-indent: 1.2em)

#show heading: it => { v(0.8em); it; v(0.4em) }

// =========================================================
// PORTADA
// =========================================================
#align(center)[
  #v(1cm)
  // IMAGEN 0 (OPCIONAL): descomenta si tienes el logo
  // #image("images/logo_ue.png", width: 40%)
  #v(0.5cm)
  #text(size: 13pt, weight: "bold")[TÉCNICAS DE HACKING]
  #v(0.3cm)
  #line(length: 80%)
  #v(0.5cm)
  #text(size: 20pt, weight: "bold")[Práctica 2: Reconocimiento Activo]
  #v(0.5cm)
  #line(length: 80%)
  #v(0.8cm)
  #text(size: 12pt)[JJ]
  #v(0.2cm)
  #text(size: 11pt, style: "italic")[Universidad Europea de Madrid]
  #v(0.2cm)
  #text(size: 11pt)[#datetime.today().display("[day]/[month]/[year]")]
  #v(1.5cm)
]

// =========================================================
// RESUMEN
// =========================================================
#align(center)[#text(weight: "bold")[Resumen]]

#par(first-line-indent: 0em)[
  En esta práctica se estudia el reconocimiento activo de redes, una fase esencial
  en cualquier auditoría de ciberseguridad. A diferencia del reconocimiento pasivo,
  el reconocimiento activo implica el envío deliberado de paquetes de red a los
  sistemas objetivo para deducir qué equipos están encendidos y qué servicios
  ofrecen — en términos no técnicos, se llama a la puerta de cada casa del vecindario
  para ver quién está en casa. Se ha implementado en Python la función
  `craft_discovery_pkts` usando la librería Scapy, que construye paquetes de
  descubrimiento basados en los protocolos ICMP Timestamp, TCP ACK y UDP. Además,
  se analiza el comportamiento por defecto de Nmap para comprender qué mensajes envía
  y cómo clasifica el estado de los puertos. Todas las pruebas se realizaron sobre
  contenedores Docker en cumplimiento de las restricciones legales y éticas.
]

#v(0.5cm)
#line(length: 100%)

// =========================================================
// ÍNDICE
// =========================================================
#pagebreak()
#outline(title: "Índice", indent: 2em)

// =========================================================
// CUERPO
// =========================================================
#pagebreak()

= Introducción

El reconocimiento activo es la segunda fase de la metodología de auditoría de
seguridad ofensiva, inmediatamente posterior al reconocimiento pasivo
@mcnab2017network. Mientras el reconocimiento pasivo recopila información sin
interactuar con el objetivo, el reconocimiento activo implica el envío deliberado
de tráfico de red para provocar respuestas que revelen el estado y configuración
de los sistemas.

Esta fase permite determinar qué equipos están activos en la red y qué puertos
tienen servicios escuchando (abiertos), cuáles los rechazan (cerrados) y cuáles
están protegidos por filtrado (filtrados). Esta información es imprescindible
para planificar las fases posteriores de la auditoría.

En esta práctica se abordan dos bloques. El primero implementa un descubridor
de hosts usando Scapy @biondi2003scapy @scapy_docs, empleando paquetes ICMP
Timestamp @postel1981icmp, TCP ACK @postel1981tcp y UDP @postel1980udp. El segundo
analiza el comportamiento por defecto de Nmap @lyon2009nmap @nmap_manpage, la
herramienta de escaneo más usada en la industria. Todo el trabajo experimental se
realizó sobre un entorno Docker en Kali Linux.

= Desarrollo

== Descubrimiento de hosts con Scapy

=== La librería Scapy

Scapy es una librería de manipulación de paquetes escrita en Python que permite
construir paquetes de red arbitrarios en cada capa del modelo OSI, enviarlos y
analizar las respuestas @biondi2003scapy. La función central usada es `sr()`
(_send and receive_): envía paquetes y devuelve dos listas, los que obtuvieron
respuesta y los que no. Esta distinción es la base del descubrimiento de hosts.

=== Protocolos de descubrimiento

#par(first-line-indent: 0em)[*ICMP Timestamp Request (tipo 13 / tipo 14)*]

El protocolo ICMP @postel1981icmp incluye el tipo 13 (_Timestamp Request_): el
emisor solicita al receptor su hora actual. Si el host está activo, responde con
tipo 14 (_Timestamp Reply_). La ventaja frente al ping (tipo 8) es que algunos
cortafuegos bloquean Echo Request pero permiten Timestamp, ampliando la cobertura.

#par(first-line-indent: 0em)[*TCP ACK Scan*]

El TCP ACK Scan envía un segmento TCP con el flag ACK activado sin haber iniciado
ninguna conexión previa @postel1981tcp. El host responde con RST porque el sistema
operativo no reconoce la sesión TCP a la que pertenecería ese ACK, independientemente
de si el puerto destino está abierto o cerrado. Muchos cortafuegos permiten el tráfico
ACK pensando que pertenece a una sesión legítima, lo que hace esta técnica eficaz.

#par(first-line-indent: 0em)[*UDP Discovery*]

Al enviar un datagrama UDP a un puerto sin servicio en un host activo, el sistema
genera ICMP tipo 3 código 3 (_Port Unreachable_) @postel1981icmp, confirmando la
presencia del host @postel1980udp. Si el puerto tiene un servicio escuchando, puede
que no haya respuesta, haciendo la interpretación más ambigua.

=== Implementación: función `craft_discovery_pkts`

La función recibe los siguientes argumentos:

- `protocols`: lista de hasta 3 protocolos (`"ICMP"`, `"TCP"`, `"UDP"`) o un solo string.
- `ip_range`: IP o rango en formato Scapy (p.ej. `"172.20.0.0/24"`).
- `pkt_count` _(opcional)_: diccionario `{protocolo: n_paquetes}`. Por defecto 1.
- `port` _(opcional)_: puerto TCP/UDP destino. Por defecto 80.

La función itera sobre cada protocolo y construye el paquete apilando capas con
el operador `/` de Scapy: `IP(dst=...) / ICMP(type=13)` para ICMP Timestamp,
`IP(dst=...) / TCP(dport=port, flags="A")` para TCP ACK y
`IP(dst=...) / UDP(dport=port)` para UDP. Todos los paquetes se acumulan en una
lista y se retornan. Para el envío y detección se usa `sr()`, clasificando las
respuestas en respondidas y no respondidas.

== Comportamiento por defecto de Nmap y estado de puertos

=== Estado de un puerto

Nmap @lyon2009nmap clasifica los puertos en tres estados según el estímulo y
la respuesta:

#par(first-line-indent: 0em)[*Abierto (_open_)*: Hay un servicio escuchando. El sistema acepta conexiones.]

#par(first-line-indent: 0em)[*Cerrado (_closed_)*: El host está activo pero no hay servicio en ese puerto. El sistema responde indicando el rechazo.]

#par(first-line-indent: 0em)[*Filtrado (_filtered_)*: Un cortafuegos intercepta los paquetes antes de llegar al puerto. No es posible determinar si hay servicio.]

=== Estímulos y respuestas por estado

#figure(
  table(
    columns: (1fr, 1.5fr, 1.5fr),
    align: (center, left, left),
    fill: (_, row) => if row == 0 { rgb("#2c3e50") } else if calc.odd(row) { rgb("#ecf0f1") } else { white },
    text(fill: white, weight: "bold")[Estado],
    text(fill: white, weight: "bold")[Estímulo enviado],
    text(fill: white, weight: "bold")[Respuesta recibida],
    [*Abierto*],   [TCP SYN al puerto], [TCP SYN+ACK],
    [*Cerrado*],   [TCP SYN al puerto], [TCP RST],
    [*Filtrado*],  [TCP SYN al puerto], [Sin respuesta o ICMP Unreachable],
  ),
  caption: [Estados de puerto según estímulo y respuesta en TCP SYN scan.]
) <tabla_estados>

=== Comportamiento por defecto de Nmap

Al ejecutar `nmap <objetivo>` como root, Nmap realiza dos fases @nmap_manpage:

#par(first-line-indent: 0em)[*Fase 1 — Descubrimiento de host*: Envía cuatro sondas: ICMP Echo Request, TCP SYN al 443, TCP ACK al 80 e ICMP Timestamp. Si el host no responde a ninguna, no se escanea.]

#par(first-line-indent: 0em)[*Fase 2 — Escaneo de puertos*: TCP SYN Scan (`-sS`) sobre los 1.000 puertos más comunes. Al recibir SYN+ACK (abierto), Nmap responde con RST para no completar la conexión — de ahí el nombre _half-open_ o _stealth scan_. RST indica cerrado; sin respuesta o ICMP Unreachable indica filtrado.]

= Resultados

== Entorno de simulación

Las pruebas se realizaron con dos contenedores Docker en Kali Linux:

- `172.20.0.1` — Gateway de la red Docker (host Kali).
- `172.20.0.2` — Contenedor `nginx_p2`: servidor web Nginx, puerto 80 abierto.
- `172.20.0.3` — Contenedor `ssh_p2`: servidor OpenSSH, puerto 22 abierto.
- `172.20.0.200` — IP sin asignar, usada como control negativo.

== Parte 1: Descubrimiento de hosts con Scapy

La función `craft_discovery_pkts` se ejecutó sobre el rango `172.20.0.0/24`
con los tres protocolos. Los resultados se presentan en la @tabla_hosts_activos.

#figure(
  table(
    columns: (1.2fr, 1fr, 1.8fr, 1fr),
    align: (center, center, left, center),
    fill: (_, row) => if row == 0 { rgb("#2c3e50") } else if calc.odd(row) { rgb("#ecf0f1") } else { white },
    text(fill: white, weight: "bold")[IP destino],
    text(fill: white, weight: "bold")[Protocolo],
    text(fill: white, weight: "bold")[Respuesta obtenida],
    text(fill: white, weight: "bold")[Estado],
    [172.20.0.1],   [ICMP type=13], [ICMP type=14 (Timestamp Reply)],      [*Activo*],
    [172.20.0.1],   [TCP ACK],      [TCP RST],                             [*Activo*],
    [172.20.0.1],   [UDP p:80],     [ICMP Port Unreachable (t=3, c=3)],    [*Activo*],
    [172.20.0.2],   [ICMP type=13], [ICMP type=14 (Timestamp Reply)],      [*Activo*],
    [172.20.0.2],   [TCP ACK],      [TCP RST],                             [*Activo*],
    [172.20.0.2],   [UDP p:80],     [Sin respuesta (Nginx escucha p:80)],  [Indeterminado],
    [172.20.0.3],   [ICMP type=13], [ICMP type=14 (Timestamp Reply)],      [*Activo*],
    [172.20.0.3],   [TCP ACK],      [TCP RST],                             [*Activo*],
    [172.20.0.3],   [UDP p:80],     [ICMP Port Unreachable (t=3, c=3)],    [*Activo*],
    [172.20.0.200], [ICMP type=13], [Sin respuesta (timeout 2s)],          [Inactivo],
    [172.20.0.200], [TCP ACK],      [Sin respuesta (timeout 2s)],          [Inactivo],
    [172.20.0.200], [UDP p:80],     [Sin respuesta (timeout 2s)],          [Inactivo],
  ),
  caption: [Resultados del descubrimiento de hosts con `craft_discovery_pkts`.]
) <tabla_hosts_activos>

La combinación de tres protocolos aumenta la robustez: en `172.20.0.2` el UDP no
generó respuesta porque Nginx estaba escuchando en el 80, pero ICMP y TCP ACK sí
confirmaron el host activo. El host inactivo `172.20.0.200` no generó respuesta
en ningún protocolo.

// =========================================================
// IMAGEN 1: Captura de terminal del script host_discovery.py
//
// Pasos para obtenerla:
//   sudo python3 src/host_discovery.py
//   Haz screenshot de la terminal y guárdala como:
//   doc/images/img1_script_output.png
// =========================================================
#figure(
  image("images/img1_script_output.png", width: 90%),
  caption: [Salida del script `host_discovery.py` ejecutado sobre la red `172.20.0.0/24`.
            Se aprecian los hosts que respondieron y el host inactivo sin respuesta.]
) <img_script>

// =========================================================
// IMAGEN 2: Captura Wireshark — ICMP Timestamp (type 13 y 14)
//
// Pasos:
//   1. Abre Wireshark, selecciona la interfaz del docker (br-XXXX)
//      Para encontrarla: ip link show | grep br-
//   2. Filtro Wireshark: icmp.type == 13 || icmp.type == 14
//   3. Ejecuta: sudo python3 src/host_discovery.py
//   4. Haz screenshot y guarda como: doc/images/img2_wireshark_icmp.png
// =========================================================
#figure(
  image("images/img2_wireshark_icmp.png", width: 90%),
  caption: [Captura Wireshark del intercambio ICMP Timestamp. Se observa la petición
            (type=13) desde Kali y la respuesta (type=14) del host activo.]
) <img_wireshark_icmp>

// =========================================================
// IMAGEN 3: Captura Wireshark — TCP ACK → RST
//
// Pasos:
//   1. Wireshark en la misma interfaz del docker
//   2. Filtro: tcp.flags.ack == 1 || tcp.flags.rst == 1
//   3. Ejecuta el script y haz screenshot
//   4. Guarda como: doc/images/img3_wireshark_tcp_ack.png
// =========================================================
#figure(
  image("images/img3_wireshark_tcp_ack.png", width: 90%),
  caption: [Captura Wireshark del TCP ACK Scan. El paquete ACK enviado provoca
            una respuesta RST del host activo, confirmando su presencia.]
) <img_wireshark_tcp>

== Parte 2: Comportamiento por defecto de Nmap

Para analizar Nmap se ejecutó `sudo nmap 172.20.0.2` mientras se capturaba el
tráfico con Wireshark. Se observaron dos fases diferenciadas.

#par(first-line-indent: 0em)[*Fase 1 — Descubrimiento*: Nmap envió cuatro sondas (ICMP Echo, SYN/443, ACK/80, ICMP Timestamp) antes de iniciar el escaneo de puertos. El host respondió.]

#par(first-line-indent: 0em)[*Fase 2 — Escaneo*: 1.000 paquetes TCP SYN a los puertos más comunes. Puerto 80 respondió con SYN+ACK (abierto). El resto respondió con RST (cerrado) o no respondió (filtrado).]

// =========================================================
// IMAGEN 4: Salida de terminal de nmap
//
// Pasos:
//   sudo nmap 172.20.0.2
//   sudo nmap 172.20.0.3
//   Haz screenshot de ambas salidas y guarda como:
//   doc/images/img4_nmap_output.png
// =========================================================
#figure(
  image("images/img4_nmap_output.png", width: 85%),
  caption: [Salida de `sudo nmap 172.20.0.2`. Se identifican el puerto 80 abierto,
            el resto cerrados, y el resumen del escaneo.]
) <img_nmap_terminal>

// =========================================================
// IMAGEN 5: Captura Wireshark del escaneo nmap (SYN scan)
//
// Pasos:
//   Terminal 1: sudo tcpdump -i br-XXXX host 172.20.0.2 -w /tmp/nmap.pcap
//   Terminal 2: sudo nmap 172.20.0.2
//   Abre /tmp/nmap.pcap con Wireshark
//   Filtro: tcp.flags.syn==1 && !tcp.flags.ack==1
//   Haz screenshot mostrando SYN → SYN+ACK y SYN → RST
//   Guarda como: doc/images/img5_wireshark_nmap.png
// =========================================================
#figure(
  image("images/img5_wireshark_nmap.png", width: 90%),
  caption: [Captura Wireshark del tráfico generado por Nmap. Se distinguen los paquetes
            SYN del escaneo y las respuestas SYN+ACK (puerto abierto) y RST (cerrado).]
) <img_wireshark_nmap>

#figure(
  table(
    columns: (0.9fr, 0.9fr, 1fr, 1.4fr, 1.4fr, 0.9fr),
    align: (center, center, center, left, left, center),
    fill: (_, row) => if row == 0 { rgb("#2c3e50") } else if calc.odd(row) { rgb("#ecf0f1") } else { white },
    text(fill: white, weight: "bold")[Host],
    text(fill: white, weight: "bold")[Puerto],
    text(fill: white, weight: "bold")[Servicio],
    text(fill: white, weight: "bold")[Estímulo],
    text(fill: white, weight: "bold")[Respuesta],
    text(fill: white, weight: "bold")[Estado],
    [172.20.0.2], [80/tcp],   [http],    [TCP SYN], [TCP SYN+ACK], [*Abierto*],
    [172.20.0.2], [443/tcp],  [https],   [TCP SYN], [TCP RST],     [Cerrado],
    [172.20.0.2], [22/tcp],   [ssh],     [TCP SYN], [TCP RST],     [Cerrado],
    [172.20.0.3], [22/tcp],   [ssh],     [TCP SYN], [TCP SYN+ACK], [*Abierto*],
    [172.20.0.3], [80/tcp],   [http],    [TCP SYN], [TCP RST],     [Cerrado],
    [172.20.0.3], [443/tcp],  [https],   [TCP SYN], [TCP RST],     [Cerrado],
  ),
  caption: [Resultados del escaneo Nmap sobre los contenedores Docker.]
) <tabla_nmap_resultados>

#figure(
  table(
    columns: (1.8fr, 1fr),
    align: (left, center),
    fill: (_, row) => if row == 0 { rgb("#2c3e50") } else if calc.odd(row) { rgb("#ecf0f1") } else { white },
    text(fill: white, weight: "bold")[Parámetro],
    text(fill: white, weight: "bold")[Valor],
    [Tipo de escaneo por defecto (root)],    [TCP SYN Scan (`-sS`)],
    [Puertos escaneados],                    [1.000 más comunes],
    [Paquetes SYN enviados (mínimo)],        [1.000],
    [Reintentos sin respuesta],              [2 (`--max-retries`)],
    [Sondas de descubrimiento de host],      [4 (ICMP Echo, SYN/443, ACK/80, ICMP TS)],
    [Velocidad por defecto],                 [T3 (normal)],
    [Resolución DNS inversa],                [Sí (hosts activos)],
  ),
  caption: [Parámetros del comportamiento por defecto de Nmap.]
) <tabla_nmap_resumen>

= Conclusiones

A lo largo de la práctica se ha verificado que el reconocimiento activo requiere
combinar múltiples técnicas para maximizar la cobertura. El ICMP Timestamp ofrece
una alternativa al ping clásico menos filtrada por cortafuegos. El TCP ACK aprovecha
el comportamiento estándar del stack TCP @postel1981tcp para detectar hosts incluso
cuando los puertos están cerrados. El UDP es útil cuando el servicio no escucha en
el puerto de destino, aunque la ausencia de respuesta es ambigua.

Respecto a Nmap @lyon2009nmap, se confirmó que el TCP SYN Scan por defecto es
eficiente al no completar el _three-way handshake_, dejando menos rastros en los
logs. La clasificación en tres estados (abierto, cerrado, filtrado) responde
directamente a la presencia o ausencia de respuesta y al tipo de flag TCP observado.

Desde el punto de vista ético, todas estas técnicas deben aplicarse únicamente
sobre entornos propios o con autorización explícita. Su uso no autorizado constituye
una infracción legal en la mayoría de jurisdicciones.

#bibliography("bibliography.bib", title: "Bibliografía", style: "ieee")
