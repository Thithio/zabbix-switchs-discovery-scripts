# zabbix-switchs-discovery-scripts

[![CI](https://github.com/Thithio/zabbix-switchs-discovery-scripts/actions/workflows/ci.yml/badge.svg)](https://github.com/Thithio/zabbix-switchs-discovery-scripts/actions/workflows/ci.yml) ![Licença MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-blue)

Scripts em Python que varrem uma faixa de IPs por SNMP, encontram switches de acesso e cadastram no Zabbix os que ainda não existem, já com template, grupos e interface SNMP. No fim, mandam um e-mail com a lista de hosts criados.

Nasceram para manter o inventário de switches de campus em dia sem cadastro manual.

## Scripts

| Script | Fabricante | SNMP | Biblioteca |
|---|---|---|---|
| `discoverySwCisco.py` | Cisco | v2c (community) | `pysnmp` (asyncio) |
| `discoverySwHuawei.py` | Huawei | v3 (SHA-256 / AES-256) | `easysnmp` |

## Como funcionam

1. Percorrem a faixa de IPs configurada (ex.: `192.168.90.1-252`) e leem o `sysName` de cada equipamento (OID `1.3.6.1.2.1.1.5.0`).
2. Ignoram tudo cujo `sysName` não comece com `SW`, para não cadastrar o que não é switch.
3. Consultam a API do Zabbix (`host.get`) e pulam os hosts que já existem.
4. Criam os novos hosts com interface SNMP na porta 161, os templates e os grupos definidos no topo do script, e a descrição padrão do time dono.
5. Enviam um e-mail pelo relay SMTP com o que foi criado (HTML no Cisco, texto no Huawei, que inclui as instruções de SNMPv3).

Testado com Zabbix 7.0.

## Configuração

Os valores sensíveis estão como placeholders no topo de cada script. Antes de rodar, preencha:

- SNMP: community (Cisco) ou usuário e senhas SNMPv3 (Huawei), e a faixa de IPs.
- Zabbix: URL da API (`https://seu-zabbix/api_jsonrpc.php`), usuário e senha, templates e grupos.
- E-mail: servidor e porta do relay, remetente e destinatário.

Não versione credenciais reais. Se for rodar em produção, leia esses valores de variáveis de ambiente ou de um cofre de segredos.

## Requisitos

```bash
pip install -r requirements.txt   # o easysnmp precisa da net-snmp instalada no sistema
```

## Uso

```bash
python3 discoverySwCisco.py
python3 discoverySwHuawei.py
```

Dá para agendar no cron do servidor do Zabbix para a descoberta rodar sozinha.

Veja também [ansible-snmpv3-switches](https://github.com/Thithio/ansible-snmpv3-switches), que configura SNMPv3 e trap nos mesmos switches.

## Licença

MIT
