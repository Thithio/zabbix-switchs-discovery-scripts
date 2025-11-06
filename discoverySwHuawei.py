#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
descoberta_sw_huawei_zabbix_v3_easysnmp.py (public-safe)
Descobre switches Huawei via SNMPv3 (SHA-256/AES256) usando easysnmp.
Cria hosts novos no Zabbix 7.0 se ainda não existirem.
Ao final, envia e-mail listando os hosts criados e instruções de SNMPv3.

>> Public version: todos os dados sensíveis foram substituídos por placeholders.
"""

import re
import sys
import time
import signal
import smtplib
import requests
import warnings
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.header import Header
from email.utils import formataddr
from easysnmp import Session

warnings.filterwarnings('ignore', message='Unverified HTTPS request')

# =========================
# Configurações SNMPv3
# =========================
SNMP_USER = "<SNMP_USER>"
SNMP_AUTH_PASS = "<SNMP_AUTH_PASS>"
SNMP_PRIV_PASS = "<SNMP_PRIV_PASS>"
AUTH_PROTOCOL = "SHA256"
PRIV_PROTOCOL = "AES256"
OID_SYSNAME = "1.3.6.1.2.1.1.5.0"
IP_RANGE = "<IP_RANGE>"  # ex: 192.168.90.1-252
TIMEOUT = 2

# =========================
# Configurações Zabbix
# =========================
ZABBIX_URL = "<ZABBIX_URL>"  # ex: https://seu-zabbix/api_jsonrpc.php
ZABBIX_USER = "<ZABBIX_USER>"
ZABBIX_PASSWORD = "<ZABBIX_PASSWORD>"
TEMPLATES = ["Huawei VRP by SNMP"]  # mantido a pedido (não sensível)
GROUPS_PADRAO = ["Switches", "SWITCHES CAMPUS - ACESSO", "HUAWEI"]  # mantido a pedido
HOST_DESCRIPTION = "Network Team"  # altere se quiser

# =========================
# Configurações de E-mail (relay)
# =========================
SMTP_SERVER = "<SMTP_SERVER>"   # ex: 172.20.0.25
SMTP_PORT = 25
EMAIL_FROM = "relay@example.com"
EMAIL_TO = "<EMAIL_TO>"         # ex: voce@example.com
EMAIL_SUBJECT = "📡 [Zabbix] Novos hosts Huawei criados via descoberta SNMPv3"

# -------------------------------------------------------------------
# Funções auxiliares Zabbix API
# -------------------------------------------------------------------
def zbx_request(payload):
    resp = requests.post(ZABBIX_URL, json=payload, verify=False)
    data = resp.json()
    if "error" in data:
        raise Exception(data["error"])
    return data["result"]

def zbx_login():
    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {"username": ZABBIX_USER, "password": ZABBIX_PASSWORD},
        "id": 1
    }
    return zbx_request(payload)

def zbx_get_groupid(auth, name):
    payload = {
        "jsonrpc": "2.0", "method": "hostgroup.get",
        "params": {"filter": {"name": [name]}},
        "auth": auth, "id": 1
    }
    result = zbx_request(payload)
    if result:
        return result[0]["groupid"]
    payload = {
        "jsonrpc": "2.0", "method": "hostgroup.create",
        "params": {"name": name},
        "auth": auth, "id": 1
    }
    return zbx_request(payload)["groupids"][0]

def zbx_get_templateid(auth, name):
    payload = {
        "jsonrpc": "2.0", "method": "template.get",
        "params": {"filter": {"name": [name]}},
        "auth": auth, "id": 1
    }
    result = zbx_request(payload)
    if not result:
        raise Exception(f"Template '{name}' não encontrado no Zabbix.")
    return result[0]["templateid"]

def zbx_get_hostid(auth, name):
    payload = {
        "jsonrpc": "2.0", "method": "host.get",
        "params": {"filter": {"host": [name]}},
        "auth": auth, "id": 1
    }
    result = zbx_request(payload)
    return result[0]["hostid"] if result else None

def sanitize_host_name(name: str):
    return re.sub(r'[^A-Za-z0-9_.\-]', '_', name)

def zbx_create_host_minimal(auth, ip, host_name, group_ids, template_ids):
    """Cria host SNMPv3 (mínimo necessário) sem DNS."""
    host_clean = sanitize_host_name(host_name)
    if zbx_get_hostid(auth, host_clean):
        print(f"⚙️  Host já existe: {host_clean} — ignorado.")
        return False

    interface = {
        "type": 2,  # SNMP
        "main": 1,
        "useip": 1,
        "ip": ip,
        "dns": "",
        "port": "161",
        "details": {
            "version": 3,
            "bulk": 0,
            "contextname": "",
            "securityname": SNMP_USER,
            "securitylevel": 3  # ajuste no Zabbix se necessário
        }
    }
    payload = {
        "jsonrpc": "2.0",
        "method": "host.create",
        "params": {
            "host": host_clean,
            "name": host_name,
            "description": HOST_DESCRIPTION,
            "interfaces": [interface],
            "groups": [{"groupid": gid} for gid in group_ids],
            "templates": [{"templateid": tid} for tid in template_ids]
        },
        "auth": auth,
        "id": 1
    }
    zbx_request(payload)
    print(f"🆕 Host criado: {host_clean}")
    return True

# -------------------------------------------------------------------
# SNMP Discovery
# -------------------------------------------------------------------
def ip_range_to_list(ip_range: str):
    if "-" not in ip_range:
        return [ip_range.strip()]
    base = ".".join(ip_range.split(".")[:3])
    start, end = ip_range.split(".")[-1].split("-")
    return [f"{base}.{i}" for i in range(int(start), int(end) + 1)]

def snmp_get_sysname(ip):
    try:
        session = Session(
            hostname=ip, version=3,
            security_level="authPriv",
            security_username=SNMP_USER,
            auth_protocol=AUTH_PROTOCOL, auth_password=SNMP_AUTH_PASS,
            privacy_protocol=PRIV_PROTOCOL, privacy_password=SNMP_PRIV_PASS,
            timeout=TIMEOUT, retries=0
        )
        result = session.get(OID_SYSNAME)
        return result.value
    except Exception as e:
        print(f"[debug] {ip}: {e}")
        return None

# -------------------------------------------------------------------
# Envio de e-mail via relay SMTP
# -------------------------------------------------------------------
def send_email_smtp(subject, body, to_email):
    try:
        msg = MIMEMultipart()
        msg['From'] = formataddr((str(Header('Zabbix Descoberta SNMPv3', 'utf-8')), EMAIL_FROM))
        msg['To'] = to_email
        msg['Subject'] = Header(subject, 'utf-8')
        msg.attach(MIMEText(body, 'plain', 'utf-8'))
        with smtplib.SMTP(SMTP_PORT) as _:
            pass  # placeholder para ambientes sem SMTP; substitua abaixo
        # --- Versão real (substitua o bloco acima por este quando preencher) ---
        # with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
        #     server.sendmail(EMAIL_FROM, to_email, msg.as_string())
        print(f"📧 (simulado) E-mail enviado para {to_email}")
    except Exception as e:
        print(f"⚠️ Erro ao enviar e-mail: {e}")

# -------------------------------------------------------------------
# Ctrl+C handler
# -------------------------------------------------------------------
def signal_handler(sig, frame):
    print("\n🛑 Execução interrompida pelo usuário (Ctrl+C). Encerrando...\n")
    sys.exit(0)
signal.signal(signal.SIGINT, signal_handler)

# -------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------
def main():
    ips = ip_range_to_list(IP_RANGE)
    novos = existentes = ignorados = sem_resposta = 0
    created_hosts = []

    print("[+] Autenticando no Zabbix...")
    auth = zbx_login()
    group_ids = [zbx_get_groupid(auth, g) for g in GROUPS_PADRAO]
    template_ids = [zbx_get_templateid(auth, t) for t in TEMPLATES]

    print(f"[+] Varredura SNMPv3 (easysnmp) no range {IP_RANGE}\n")

    for ip in ips:
        sysname = snmp_get_sysname(ip)
        if not sysname:
            print(f"❌ {ip} → sem resposta SNMP")
            sem_resposta += 1
            continue

        if not sysname.upper().startswith("SW"):
            print(f"⚠️  {ip} → ignorado ({sysname})")
            ignorados += 1
            continue

        host_name = sysname.split(".")[0]  # sanitiza sem expor domínio
        print(f"✅ {ip} → {host_name}")

        try:
            created = zbx_create_host_minimal(auth, ip, host_name, group_ids, template_ids)
            if created:
                novos += 1
                created_hosts.append((ip, host_name))
            else:
                existentes += 1
        except Exception as e:
            print(f"❌ Erro ao criar host {host_name}: {e}")

        time.sleep(0.2)

    print("\n[📊] Resumo da varredura:")
    print(f"   🆕 Novos hosts criados: {novos}")
    print(f"   ⚙️  Já existentes: {existentes}")
    print(f"   ⚠️  Ignorados: {ignorados}")
    print(f"   ❌ Sem resposta SNMP: {sem_resposta}")

    if created_hosts:
        body = "Os seguintes hosts Huawei foram CRIADOS no Zabbix:\n\n"
        for ip, name in created_hosts:
            body += f"• {name} ({ip})\n"

        body += """
⚠️ Falta preencher manualmente os parâmetros SNMPv3 no host (no Zabbix):

  - Authentication protocol: SHA256
  - Authentication passphrase: <SNMP_AUTH_PASS>
  - Privacy protocol: AES256
  - Privacy passphrase: <SNMP_PRIV_PASS>


Atenciosamente,
— Script de descoberta SNMPv3 (Huawei)
"""
        send_email_smtp(EMAIL_SUBJECT, body, EMAIL_TO)

    print(f"\n[+] Finalizado. {novos + existentes} switches processados.\n")


if __name__ == "__main__":
    main()
