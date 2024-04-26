from aiohttp import web
from fail2ban import fail2ban
import os

routes = web.RouteTableDef()


@routes.get("/jails")
def jails(request: web.Request):
    f2b: fail2ban = request.app["f2b"]
    return web.json_response(f2b.get_jails())

@routes.get("/{jail}/status")
def status(request: web.Request):
    f2b: fail2ban = request.app["f2b"]
    jail: str = request.match_info["jail"]
    return web.json_response(f2b.get_status(jail))

@routes.put("/{jail}/banlist/{ip:(?:[0-9]{1,3}\.){3}[0-9]{1,3}}")
def ban(request: web.Request):
    f2b: fail2ban = request.app["f2b"]
    jail: str = request.match_info["jail"]
    ip: str = request.match_info["ip"]
    return web.json_response(f2b.ban(jail, ip))


@routes.delete("/{jail}/banlist/{ip:(?:[0-9]{1,3}\.){3}[0-9]{1,3}}")
def unban(request: web.Request):
    f2b: fail2ban = request.app["f2b"]
    jail: str = request.match_info["jail"]
    ip: str = request.match_info["ip"]
    return web.json_response(f2b.unban(jail, ip))


@routes.put("/banlist/{ip:(?:[0-9]{1,3}\.){3}[0-9]{1,3}}")
def banlist_all(request: web.Request):
    f2b: fail2ban = request.app["f2b"]
    ip: str = request.match_info["ip"]
    return web.json_response({jail: f2b.ban(jail, ip) for jail in f2b.get_jails()})


@routes.delete("/banlist/{ip:(?:[0-9]{1,3}\.){3}[0-9]{1,3}}")
def unbanlist_all(request: web.Request):
    f2b: fail2ban = request.app["f2b"]
    ip: str = request.match_info["ip"]
    return web.json_response({jail: f2b.unban(jail, ip) for jail in f2b.get_jails()})


if __name__ == "__main__":
    app = web.Application()
    app.add_routes(routes)
    f2b_socket: str = os.getenv("FAIL2BAN_SOCKET",
                                "/var/run/fail2ban/fail2ban.sock")
    app["f2b"] = fail2ban(f2b_socket)
    web.run_app(app, port=5000)
