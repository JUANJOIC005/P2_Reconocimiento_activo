# P2_Reconocimiento_activo

Práctica de reconocimiento activo orientada al descubrimiento de hosts en red mediante Scapy, complementada con un análisis del comportamiento por defecto de Nmap y apoyada en un entorno de pruebas aislado con Docker.

## Descripción

Este proyecto implementa una herramienta en Python para identificar hosts activos enviando tráfico de red controlado. Se utilizan tres técnicas principales:

- ICMP Timestamp Request
- TCP ACK
- UDP

El objetivo es analizar qué hosts responden y cómo varía el comportamiento según el protocolo.

Incluye código, documentación técnica y capturas reales de la práctica.

## Objetivos

- Implementar descubrimiento activo con Scapy
- Comparar ICMP, TCP y UDP
- Analizar respuestas de red
- Estudiar comportamiento de Nmap
- Documentar resultados

## Estructura

P2_Reconocimiento_activo/
├── docker-compose.yml
├── src/
│   ├── host_discovery.py
│   ├── pyproject.toml
│   └── uv.lock
└── doc/
    ├── report.typ
    ├── report.pdf
    ├── bibliography.bib
    └── images/

## Tecnologías

- Python 3.11+
- Scapy
- Docker
- Typst
- Wireshark
- Nmap
- Kali Linux

## Entorno

Red Docker:

- 172.20.0.1 → gateway
- 172.20.0.2 → nginx (puerto 80)
- 172.20.0.3 → ssh (puerto 22)
- 172.20.0.200 → IP no usada (test)

## Requisitos

- Python 3.11+
- Docker
- Permisos root
- Linux recomendado

## Instalación

git clone git@github.com:JUANJOIC005/P2_Reconocimiento_activo.git
cd P2_Reconocimiento_activo

docker compose up -d

cd src
python3 -m venv .venv
source .venv/bin/activate
pip install scapy jupyter ipykernel

## Ejecución

sudo python3 host_discovery.py

## Funcionamiento

El script:

1. Construye paquetes (ICMP, TCP ACK, UDP)
2. Los envía a hosts
3. Analiza respuestas
4. Determina hosts activos

## Resultados

Incluye capturas de:

- Salida del script
- ICMP en Wireshark
- TCP ACK / RST
- Nmap
- Tráfico de Nmap

## Documentación

doc/report.typ → fuente  
doc/report.pdf → memoria final  
doc/bibliography.bib → referencias  

