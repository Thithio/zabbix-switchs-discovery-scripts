#!/usr/bin/env python3
"""
descoberta_snmp_zabbix.py
Descobre switches via SNMPv2c e cria hosts novos no Zabbix se ainda não existirem.
Ignora qualquer equipamento cujo sysName não comece com 'SW'.
Adiciona descrição padrão "Network Team" nos hosts criados.
Envia e-mail de notificação sempre que um novo host for criado.
"""

import asyncio
import requests
import re
import smtplib
from datetime import datetime
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr
from email.header import Header
import warnings
from pysnmp.hlapi.v3arch.asyncio import (
    get_cmd,
    SnmpEngine,
    CommunityData,
    UdpTransportTarget,
    ContextData,
    ObjectType,
    ObjectIdentity,
)

# --- configs SNMP ---
COMMUNITY = " your_community_string "
OID_SYSNAME = "1.3.6.1.2.1.1.5.0"
IP_RANGE = "172.000.20.1-252"
TIMEOUT = 1

# --- Zabbix configs ---
ZABBIX_URL = "url zabbix "
ZABBIX_USER = " exemple "
ZABBIX_PASSWORD = " exemple "
TEMPLATES = ["Template SWITCH CISCO SNMP - ACESSO"]
GROUPS_PADRAO = ["Switches", "SWITCHES CAMPUS - ACESSO", "Cisco"]
HOST_DESCRIPTION = "Network Team"

# --- E-mail  configs ---
SMTP_SERVER = " relay smtp "
SMTP_PORT = 43 # port smtp
EMAIL_FROM = "  email origem <email@origem.com>"
EMAIL_TO = " EMAIL DESTINO "
EMAIL_SUBJECT = "🆕 Novo Host Criado no Zabbix - Descoberta Cisco"

# --- Ignorar avisos SSL ---
warnings.filterwarnings("ignore", message="Unverified HTTPS request")
requests.packages.urllib3.disable_warnings()


# -----------------------------
# Send Email
# -----------------------------
def send_email_smtp(subject, body, to_email):
    """Envia e-mail via relay SMTP sem autenticação."""
    try:
        msg = MIMEMultipart()
        msg["From"] = formataddr((str(Header("Zabbix Discovery", "utf-8")), EMAIL_FROM))
        msg["To"] = to_email
        msg["Subject"] = subject

        msg.attach(MIMEText(body, "html", "utf-8"))

        with smtplib.SMTP(SMTP_SERVER, SMTP_PORT) as server:
            server.sendmail(EMAIL_FROM, to_email, msg.as_string())

        print(f"📧 E-mail enviado para {to_email}")
    except Exception as e:
        print(f"⚠️ Falha ao enviar e-mail: {e}")


# -----------------------------
# Funções auxiliares Zabbix API
# -----------------------------
def zbx_request(payload):
    response = requests.post(ZABBIX_URL, json=payload, verify=False)
    data = response.json()
    if "error" in data:
        raise Exception(data["error"])
    return data["result"]


def zbx_login():
    payload = {
        "jsonrpc": "2.0",
        "method": "user.login",
        "params": {"username": ZABBIX_USER, "password": ZABBIX_PASSWORD},
        "id": 1,
    }
    return zbx_request(payload)


def zbx_get_groupid(auth, name):
    payload = {
        "jsonrpc": "2.0",
        "method": "hostgroup.get",
        "params": {"filter": {"name": [name]}},
        "auth": auth,
        "id": 1,
    }
    result = zbx_request(payload)
    if result:
        return result[0]["groupid"]
    payload = {
        "jsonrpc": "2.0",
        "method": "hostgroup.create",
        "params": {"name": name},
        "auth": auth,
        "id": 1,
    }
    return zbx_request(payload)["groupids"][0]


def zbx_get_templateid(auth, name):
    payload = {
        "jsonrpc": "2.0",
        "method": "template.get",
        "params": {"filter": {"name": [name]}},
        "auth": auth,
        "id": 1,
    }
    result = zbx_request(payload)
    if result:
        return result[0]["templateid"]
    else:
        raise Exception(f"Template '{name}' não encontrado no Zabbix.")


def zbx_get_hostid(auth, name):
    payload = {
        "jsonrpc": "2.0",
        "method": "host.get",
        "params": {"filter": {"host": [name]}},
        "auth": auth,
        "id": 1,
    }
    result = zbx_request(payload)
    return result[0]["hostid"] if result else None


def sanitize_host_name(name: str):
    return re.sub(r"[^A-Za-z0-9_.\-]", "_", name)


def zbx_create_host(auth, ip, host_name, dns_name, group_ids, template_ids):
    host_name_clean = sanitize_host_name(host_name)
    dns_name_clean = sanitize_host_name(dns_name)

    if zbx_get_hostid(auth, host_name_clean):
        print(f"⚙️  Host já existe: {host_name_clean} — ignorado.")
        return False

    interface = {
        "type": 2,  # SNMP
        "main": 1,
        "useip": 1,
        "ip": ip,
        "dns": dns_name_clean,
        "port": "161",
        "details": {"version": 2, "community": COMMUNITY},
    }

    payload = {
        "jsonrpc": "2.0",
        "method": "host.create",
        "params": {
            "host": host_name_clean,
            "name": host_name,
            "description": HOST_DESCRIPTION,
            "interfaces": [interface],
            "groups": [{"groupid": g} for g in group_ids],
            "templates": [{"templateid": t} for t in template_ids],
        },
        "auth": auth,
        "id": 1,
    }

    zbx_request(payload)
    print(f"🆕 Host criado: {host_name_clean} ({ip})")

    # --- SEND e-mail ---
    data_hora = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    corpo_email = f"""
    <h3>🆕 Novo Host Criado no Zabbix</h3>
    <p><b>Nome:</b> {host_name}</p>
    <p><b>IP:</b> {ip}</p>
    <p><b>Descrição:</b> {HOST_DESCRIPTION}</p>
    <p><b>Data/Hora:</b> {data_hora}</p>
    <hr>
    <p>Script de descoberta SNMP — Automação de Switches Cisco.</p>
    """
    send_email_smtp(EMAIL_SUBJECT, corpo_email, EMAIL_TO)

    return True


# -----------------------------
# SNMP Discovery
# -----------------------------
def ip_range_to_list(ip_range: str):
    if "-" not in ip_range:
        return [ip_range.strip()]
    base = ".".join(ip_range.split(".")[:3])
    start, end = ip_range.split(".")[-1].split("-")
    return [f"{base}.{i}" for i in range(int(start), int(end) + 1)]


async def snmp_get_name(ip):
    try:
        target = await UdpTransportTarget.create((ip, 161), timeout=TIMEOUT)
        community = CommunityData(COMMUNITY, mpModel=1)
        errorIndication, errorStatus, errorIndex, varBinds = await get_cmd(
            SnmpEngine(),
            community,
            target,
            ContextData(),
            ObjectType(ObjectIdentity(OID_SYSNAME)),
        )
        if errorIndication or errorStatus:
            return None
        for varBind in varBinds:
            return str(varBind[1])
    except Exception:
        return None


# -----------------------------
# MAIN
# -----------------------------
async def main():
    ips = ip_range_to_list(IP_RANGE)
    novos = existentes = ignorados = sem_resposta = 0

    print("[+] Autenticando no Zabbix...")
    auth = zbx_login()
    group_ids = [zbx_get_groupid(auth, g) for g in GROUPS_PADRAO]
    template_ids = [zbx_get_templateid(auth, t) for t in TEMPLATES]

    print(f"[+] Varredura SNMP no range {IP_RANGE}\n")

    for ip in ips:
        sysname = await snmp_get_name(ip)
        if not sysname:
            print(f"❌ {ip} → sem resposta SNMP")
            sem_resposta += 1
            continue

        if not sysname.upper().startswith("SW"):
            print(f"⚠️  {ip} → ignorado ({sysname})")
            ignorados += 1
            continue

        nome_host = sysname.split(".unifor.br")[0] if ".unifor.br" in sysname else sysname
        print(f"✅ {ip} → {nome_host}")
        created = zbx_create_host(auth, ip, nome_host, sysname, group_ids, template_ids)
        if created:
            novos += 1
        else:
            existentes += 1

    print("\n[📊] Resumo da varredura:")
    print(f"   🆕 Novos hosts criados: {novos}")
    print(f"   ⚙️  Já existentes: {existentes}")
    print(f"   ⚠️  Ignorados (não SW): {ignorados}")
    print(f"   ❌ Sem resposta SNMP: {sem_resposta}")
    print(f"\n[+] Finalizado. {novos + existentes} switches processados no total.")


if __name__ == "__main__":
    asyncio.run(main())
