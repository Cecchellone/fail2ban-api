from fastapi import FastAPI
from fail2ban import fail2ban
from ipaddress import ip_address, IPv4Address, IPv6Address
import os

app = FastAPI()
f2b_socket: str = os.getenv("FAIL2BAN_SOCKET", "/var/run/fail2ban/fail2ban.sock")
f2b = fail2ban(f2b_socket)

def split_ip(ips: str, sep: str = "-") -> list[IPv4Address|IPv6Address]:
    return [ip_address(ip) for ip in ips.split(sep)]

@app.get("/jails")
def jails():
    return f2b.get_jail_list()

@app.get("/{jail}/status")
def status(jail: str):
    return f2b.jail_status(jail)

@app.get("/{jail}/banlist")
def banlist(jail: str):
    return f2b.jail_get_ban_ip(jail)

@app.put("/{jail}/banlist/{ips}")
def ban(jail: str, ips: str):
    return f2b.jail_ban_ip(jail, *split_ip(ips))

@app.delete("/{jail}/banlist/{ips}")
def unban(jail: str, ips: str):
    return f2b.jail_unban_ip(jail, *split_ip(ips))
