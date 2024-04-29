import socket
import pickle
import datetime
from enum import Enum
import re
from ipaddress import ip_address, IPv4Address, IPv6Address
from typing import NamedTuple
from json import JSONEncoder

END_COMMAND = b"<F2B_END_COMMAND>"

class loglevel(Enum):
    CRITICAL = "CRITICAL"
    ERROR = "ERROR"
    WARNING = "WARNING"
    NOTICE = "NOTICE"
    INFO = "INFO"
    DEBUG = "DEBUG"
    TRACEDEBUG = "TRACEDEBUG"
    HEAVYDEBUG = "HEAVYDEBUG"

class BanTime (NamedTuple):
    start: datetime.datetime
    duration: datetime.timedelta
    end: datetime.datetime

    def __repr__(self) -> str:
        return f"{self.start} + {int(self.duration.total_seconds())} = {self.end}"

class fail2ban:
    __address: str

    def __init__(self, address: str):
        self.__address = address

    @staticmethod
    def __parse_arguments(args: dict[str]) -> list[str]:
        arguments:list[str] = []
        for key, value in args.items():
            if isinstance(value, bool) and value == False:
                continue
        
            arguments.append("--" + key.replace("_", "-"))
        
            if not isinstance(value, bool):
                arguments.append(str(value))
        
        return arguments

    def __request(self, arguments:list[str], **flags):
        input:list[str] = list(arguments) + fail2ban.__parse_arguments(flags)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) 
        try:
            sock.connect(self.__address)
            encoded_input = pickle.dumps(input)
            sock.sendall(encoded_input)
            sock.sendall(END_COMMAND)

            buf = bytearray()
            while True:
                data = sock.recv(1)
                if not data:
                    break
                buf += data
                if buf.endswith(END_COMMAND):
                    break

            buf = buf[: -len(END_COMMAND)]

            fail2ban_output = pickle.loads(buf)

            if isinstance(fail2ban_output, tuple):
                fail2ban_output = fail2ban_output[1]
                if isinstance(fail2ban_output, tuple):
                    call = fail2ban_output[0]
                    if isinstance(call, tuple):
                        raise Exception(call[0] + ": " + call[1])

            try:
                return fail2ban.__tuple_to_dict(fail2ban_output)
            except Exception as e:
                return fail2ban_output
        finally:
            sock.close()

    @staticmethod
    def __tuple_to_dict(object) -> dict[str]:
        if isinstance(object, list) and all(
            [
                isinstance(t, tuple) and len(t) == 2 and isinstance(t[0], str)
                for t in object
            ]
        ):
            ret: dict[str] = {}
            for key, value in object:
                try:
                    value = fail2ban.__tuple_to_dict(value)
                except Exception as e:
                    pass
                ret[str(key).lower()] = value
            return ret
        else:
            raise Exception("Invalid input")

    # BASIC
    def start(self):
        """starts the server and the jails"""
        return self.__request(["start"])

    def restart(self):
        """restarts the server"""
        return self.__request(["restart"])

    def reload(self, restart: bool = False, unban: bool = False, all: bool = False):
        """reloads the configuration without restarting of the server, the option '--restart' activates completely restarting of affected jails, thereby can unban IP addresses (if option '--unban' specified)"""
        return self.__request(
            ["reload"], restart=restart, unban=unban, all=all
        )
    
    def stop(self):
        """stops all jails and terminate the server"""
        return self.__request(["stop"])

    def unban(self, *ip: IPv4Address | IPv6Address):
        """unbans the IP address <IP> in the jail <JAIL>
        
        if no IP address is given, all IP addresses are unbanned"""
        if len(ip) == 0:
            return self.__request(["unban"], all=True)
        else:
            return self.__request(["unban"] + [str(i) for i in ip])

    def banned(self, *ip: IPv4Address | IPv6Address):
        """lists all banned IP addresses

        if at least one IP address is given, return list(s) of jails where given IP(s) are banned"""
        if len(ip) == 0:
            return self.__request(["banned"])
        else:
            return self.__request(["banned"] + [str(i) for i in ip])

    def status(self):
        """gets the current status of the server"""
        return self.__request(["status"])

    def get_jail_list(self) -> list[str]:
        """gets the list of jails"""
        jails:str = self.status().get("jail list")
        if jails:
            return jails.split(", ")
        else:
            return []

    def ping(self):
        """tests if the server is alive"""
        return self.__request(["ping"])

    def echo(self):
        """for internal usage, returns back and outputs a given string"""
        return self.__request(["echo"])
    
    # def help(self):
    #     """displays this help"""
    #     return self.__request(["help"])

    def version(self):
        """return the server version"""
        return self.__request(["version"])

    # LOGGING
    def set_loglevel(self, level: loglevel) -> None:
        """sets logging level to <LEVEL>. Levels: CRITICAL, ERROR, WARNING, NOTICE, INFO, DEBUG, TRACEDEBUG, HEAVYDEBUG or corresponding numeric value (50-5)"""
        self.__request(["set", "loglevel", level.value])

    def get_loglevel(self) -> loglevel|int:
        """gets the logging level"""
        stdout = self.__request(["get", "loglevel"])
        match = re.match(r"^Current logging level is \'([A-Z]+|\d{1,2})\'$", stdout)
        if match is None:
            raise Exception("Invalid output")
        level:str = match.group(1)
        if level.isdigit():
            return int(level)
        else:
            return loglevel(level)

    def set_log_target(self, target: str):
        """sets logging target to <TARGET>. Can be STDOUT, STDERR, SYSLOG or a file"""
        return self.__request(["set", "logtarget", target])

    def get_log_target(self):
        """gets logging target"""
        return self.__request(["get", "logtarget"])
    
    def set_syslog_socket(self, socket: str = "auto"):
        """sets the syslog socket path to auto or <SOCKET>. Only used if logtarget is SYSLOG"""
        return self.__request(["set", "syslogsocket", socket])
    
    def get_syslog_socket(self):
        """gets the syslog socket path"""
        return self.__request(["get", "syslogsocket"])
    
    def flush_logs(self):
        """flushes the logtarget if a file and reopens it.
        
        For log rotation."""
        return self.__request(["flushlogs"])
    
    # DATABASE
    def set_db_file(self, file: str = None):
        """set the location of fail2ban persistent datastore. Set to "None" to disable"""
        return self.__request(["set", "dbfile", file])
    
    def get_db_file(self):
        """get the location of fail2ban persistent datastore"""
        return self.__request(["get", "dbfile"])
    
    def set_db_max_matches(self, matches: int):
        """sets the max number of matches stored in database per ticket"""
        return self.__request(["set", "dbmaxmatches", matches])
    
    def get_db_max_matches(self):
        """gets the max number of matches stored in database per ticket"""
        return self.__request(["get", "dbmaxmatches"])
    
    def set_db_purge_age(self, seconds: int):
        """sets the max age in <SECONDS> that history of bans will be kept"""
        return self.__request(["set", "dbpurgeage", seconds])

    def get_db_purge_age(self):
        """gets the max age in seconds that history of bans will be kept"""
        return self.__request(["get", "dbpurgeage"])

    # JAIL CONTROL
    def jail_add(self, jail:str, backend: str):
        """creates <JAIL> using <BACKEND>"""
        return self.__request(["add", jail, backend])

    def jail_start(self, jail:str):
        """starts the jail <JAIL>"""
        return self.__request(["start", jail])
    
    def jail_restart(self, jail:str, unban: bool = False, if_exist: bool = False):
        """restarts the jail <JAIL> (alias for 'reload --restart ... <JAIL>')"""
        return self.__request(["restart", jail], unban=unban, if_exist=if_exist)

    def jail_reload(self, jail:str, restart: bool = False, unban: bool = False, if_exist: bool = False):
        """reloads the jail <JAIL>, or restarts it (if option '--restart' specified)"""
        if restart:
            return self.jail_restart(jail, unban, if_exist)
        else:
            return self.__request(["reload", jail], unban=unban, if_exist=if_exist)

    def jail_stop(self, jail:str):
        """stops the jail <JAIL>. The jail is removed"""
        return self.__request(["stop", jail])

    def jail_status(self, jail:str, flavor: str = None):
        """gets the current status of <JAIL>, with optional flavor or extended info"""
        return self.__request(["status", jail] + ([flavor] if flavor else []))

    # JAIL CONFIGURATION
    def jail_set_idle(self, jail:str, idle: bool):
        """sets the idle state of <JAIL>"""
        return self.__request(["set", jail, "idle", "on" if idle else "off"])

    def jail_set_ignore_self(self, jail:str, ignore: bool):
        """allows the ignoring of own IP addresses"""
        return self.__request(["set", jail, "ignoreself", "true" if ignore else "false"])

    def jail_add_ignore_ip(self, jail:str, ip: IPv4Address | IPv6Address):
        """adds <IP> to the ignore list of <JAIL>"""
        return self.__request(["set", jail, "addignoreip", str(ip)])

    def jail_del_ignore_ip(self, jail:str, ip: IPv4Address | IPv6Address):
        """removes <IP> from the ignore list of <JAIL>"""
        return self.__request(["set", jail, "delignoreip", str(ip)])

    def jail_set_ignore_command(self, jail:str, value: str):
        """sets the ignore command for <JAIL>"""
        return self.__request(["set", jail, "ignorecommand", value])
    
    def jail_set_ignore_cache(self, jail:str, value: int):
        """sets the ignore cache for <JAIL>"""
        return self.__request(["set", jail, "ignorecache", value])

    def jail_add_log_path(self, jail:str, file: str, tail: bool = False):
        """adds <FILE> to the monitoring list of <JAIL>, optionally starting at the 'tail' of the file (default 'head')."""
        return self.__request(["set", jail, "addlogpath", file] + (["tail"] if tail else []))

    def jail_del_log_path(self, jail:str, file: str):
        """removes <FILE> from the monitoring list of <JAIL>"""
        return self.__request(["set", jail, "dellogpath", file])

    def jail_set_log_encoding(self, jail:str, encoding: str):
        """sets the log file encoding for <JAIL>"""
        return self.__request(["set", jail, "logencoding", encoding])
    
    def jail_add_journal_match(self, jail:str, match: str):
        """adds <MATCH> to the journal match list of <JAIL>"""
        return self.__request(["set", jail, "addjournalmatch", match])
    
    def jail_del_journal_match(self, jail:str, match: str):
        """removes <MATCH> from the journal match list of <JAIL>"""
        return self.__request(["set", jail, "deljournalmatch", match])

    def jail_add_fail_regex(self, jail:str, regex: str):
        """adds the regular expression <REGEX> which must match failures for <JAIL>"""
        return self.__request(["set", jail, "addfailregex", regex])

    def jail_del_fail_regex(self, jail:str, regex: str):
        """removes the regular expression at <INDEX> for failregex"""
        return self.__request(["set", jail, "delfailregex", regex])
    
    def jail_add_ignore_regex(self, jail:str, regex: str):
        """adds the regular expression <REGEX> which must match failures for <JAIL>"""
        return self.__request(["set", jail, "addignoreregex", regex])
    
    def jail_del_ignore_regex(self, jail:str, regex: str):
        """removes the regular expression at <INDEX> for ignoreregex"""
        return self.__request(["set", jail, "delignoreregex", regex])

    def jail_set_find_time(self, jail:str, seconds: int):
        """sets the number of seconds <SECONDS> for which the filter will look back for <JAIL>"""
        return self.__request(["set", jail, "findtime", seconds])

    def jail_set_ban_time(self, jail:str, seconds: int):
        """sets the number of seconds <SECONDS> a host will be banned for <JAIL>"""
        return self.__request(["set", jail, "bantime", seconds])

    def jail_set_date_pattern(self, jail:str, pattern: str):
        """sets the <PATTERN> used to match date/times for <JAIL>"""
        return self.__request(["set", jail, "datepattern", pattern])

    def jail_set_use_dns(self, jail:str):
        """sets the <PATTERN> used to match date/times for <JAIL>"""
        return self.__request(["set", jail, "usedns", "true"])

    def jail_set_attempt(self, jail:str, *attempts: str):
        return self.__request(["set", jail, "attempt"] + list(attempts))

    def jail_ban_ip(self, jail:str, *ip: IPv4Address | IPv6Address) -> int:
        """manually Ban <IP> for <JAIL>"""
        return self.__request(["set", jail, "banip"] + [str(i) for i in ip])

    def jail_unban_ip(self, jail:str, *ip: IPv4Address | IPv6Address, report_absent: bool = False) -> int:
        """manually Unban <IP> for <JAIL>"""
        return self.__request(["set", jail, "unbanip"] + [str(i) for i in ip])

    def jail_set_max_retry(self, jail:str, retries: int):
        """sets the number of failures <RETRY> before banning the host for <JAIL>"""
        return self.__request(["set", jail, "maxretry", retries])

    def jail_set_max_matches(self, jail:str, retry: int):
        """sets the number of failures <RETRY> before banning the host for <JAIL>"""
        return self.__request(["set", jail, "maxmatches", retry])

    def jail_set_max_lines(self, jail:str, lines: int):
        """sets the number of <LINES> to buffer for regex search for <JAIL>"""
        return self.__request(["set", jail, "maxlines", lines])

    def jail_add_action(self, jail:str, action: str, python_file: str = None, **kwargs: dict):
        """adds a new action named <ACT> for <JAIL>. Optionally for a Python based action, a <PYTHONFILE> and <JSONKWARGS> can be specified, else will be a Command Action"""
        if python_file:
            return self.__request(["set", jail, "addaction", action, python_file] + fail2ban.__parse_arguments(kwargs))
        else:
            return self.__request(["set", jail, "addaction", action])

    def jail_del_action(self, jail:str, action: str):
        """removes the action <ACT> from <JAIL"""
        return self.__request(["set", jail, "delaction", action])

    # COMMAND ACTION CONFIGURATION

    # def jail_set_cinfo(self, jail:str, act: str, key: str, value: str):
    #     return self.__request(["set", jail, "setcinfo", act, key, value])

    # def jail_del_cinfo(self, jail:str, act: str, key: str):
    #     return self.__request(["set", jail, "delcinfo", act, key])

    def jail_set_action_start(self, jail:str, action: str, command: str):
        """sets the start command <CMD> of the action <ACT> for <JAIL>"""
        return self.__request(["set", jail, "action", action, "actionstart", command])

    def jail_set_action_stop(self, jail:str, action: str, command: str):
        """sets the stop command <CMD> of the action <ACT> for <JAIL>"""
        return self.__request(["set", jail, "action", action, "actionstop", command])

    def jail_set_action_check(self, jail:str, action: str, command: str):
        """sets the check command <CMD> of the action <ACT> for <JAIL>"""
        return self.__request(["set", jail, "action", action, "actioncheck", command])

    def jail_set_action_ban(self, jail:str, action: str, command: str):
        """sets the ban command <CMD> of the action <ACT> for <JAIL>"""
        return self.__request(["set", jail, "action", action, "actionban", command])

    def jail_set_action_unban(self, jail:str, action: str, command: str):
        """sets the unban command <CMD> of the action <ACT> for <JAIL>"""
        return self.__request(["set", jail, "action", action, "actionunban", command])

    def jail_set_action_timeout(self, jail:str, action: str, seconds: int):
        """sets <SECONDS> as the command timeout in seconds for the action <ACT> for <JAIL>"""
        return self.__request(["set", jail, "action", action, "timeout", seconds])

    # GENERAL ACTION CONFIGURATION
    def jail_set_action_property(self, jail:str, action: str, property: str, value: str):
        """sets the <VALUE> of <PROPERTY> for the action <ACT> for <JAIL>"""
        return self.__request(["set", jail, "action", action, property, value])

    def jail_call_method(self, jail:str, action: str, method: str, **arguments: str):
        """calls the <METHOD> with <JSONKWARGS> for the action <ACT> for <JAIL>"""
        return self.__request(["set", jail, "action", action, method] + fail2ban.__parse_arguments(arguments))

    # JAIL INFORMATION
    def jail_get_banned(self, jail:str, *ip: IPv4Address | IPv6Address):
        """gets the list of banned IP addresses for <JAIL>

        return 1 if IP is banned in <JAIL> otherwise 0, or a list of 1/0 for multiple IPs"""
        if len(ip) == 0:
            return self.__request(["get", jail, "banned"])
        else:
            return self.__request(["get", jail, "banned"] + [str(i) for i in ip])

    def jail_log_path(self, jail:str):
        """gets the list of the monitored files for <JAIL>"""
        return self.__request(["get", jail, "logpath"])
    
    def jail_get_log_encoding(self, jail:str):
        """gets the encoding of the log files for <JAIL>"""
        return self.__request(["get", jail, "logencoding"])
    
    def jail_get_journal_match(self, jail:str):
        """gets the journal filter match for <JAIL>"""
        return self.__request(["get", jail, "journalmatch"])

    def jail_get_ignore_self(self, jail:str):
        """gets the current value of the ignoring the own IP addresses"""
        return self.__request(["get", jail, "ignoreself"])
    
    def jail_get_ignore_ip(self, jail:str):
        """gets the list of ignored IP addresses for <JAIL>"""
        return self.__request(["get", jail, "ignoreip"])

    def jail_get_ignore_command(self, jail:str):
        """gets ignorecommand of <JAIL>"""
        return self.__request(["get", jail, "ignorecommand"])
    
    def jail_get_fail_regex(self, jail:str):
        """gets the list of regular expressions which matches the failures for <JAIL>"""
        return self.__request(["get", jail, "failregex"])
    
    def jail_get_ignore_regex(self, jail:str):
        """gets the list of regular expressions which matches patterns to ignore for <JAIL>"""
        return self.__request(["get", jail, "ignoreregex"])

    def jail_get_find_time(self, jail:str):
        """gets the time for which the filter will look back for failures for <JAIL>"""
        return self.__request(["get", jail, "findtime"])

    def jail_get_ban_time(self, jail:str):
        """gets the time a host is banned for <JAIL>"""
        return self.__request(["get", jail, "bantime"])
    
    def jail_get_date_pattern(self, jail:str):
        """gets the pattern used to match date/times for <JAIL>"""
        return self.__request(["get", jail, "datepattern"])
    
    def jail_get_use_dns(self, jail:str):
        """gets the usedns setting for <JAIL>"""
        return self.__request(["get", jail, "usedns"])

    def jail_get_ban_ip(self, jail:str) -> dict[IPv4Address | IPv6Address, BanTime]:
        """gets the list of of banned IP addresses for <JAIL>. Optionally the separator character ('<SEP>', default is space) or the option '--with-time' (printing the times of ban) may be specified. The IPs are ordered by end of ban."""
        body:str = self.__request(["get", jail, "banip"], with_time=True)
        
        ips: dict[IPv4Address | IPv6Address, self.BanTime] = {}
        for line in body:
            match = re.match(r"(?P<ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s*\t+(?P<start>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}) \+ (?P<duration>\d+) = (?P<end>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2})", line)
            if match is None:
                raise Exception("Invalid output")
            ip = ip_address(match.group("ip"))
            start = datetime.datetime.strptime(match.group("start"), "%Y-%m-%d %H:%M:%S")
            duration = datetime.timedelta(seconds=int(match.group("duration")))
            end = datetime.datetime.strptime(match.group("end"), "%Y-%m-%d %H:%M:%S")
            # ips.append((ip, start, duration, end))
            ips[ip] = BanTime(start, duration, end)
        return ips
    
    def jail_get_max_retry(self, jail:str):
        """gets the number of failures allowed for <JAIL>"""
        return self.__request(["get", jail, "maxretry"])
    
    def jail_get_max_matches(self, jail:str):
        """gets the max number of matches stored in memory per ticket in <JAIL>"""
        return self.__request(["get", jail, "maxmatches"])
    
    def jail_get_max_lines(self, jail:str):
        """gets the number of lines to buffer for <JAIL>"""
        return self.__request(["get", jail, "maxlines"])
    
    def jail_get_actions(self, jail:str):
        """gets a list of actions for <JAIL>"""
        return self.__request(["get", jail, "actions"])

    # COMMAND ACTION INFORMATION
    def jail_get_action_start(self, jail:str, action: str):
        """gets the start command for the action <ACT> for <JAIL>"""
        return self.__request(["get", jail, "actionstart", action])

    def jail_get_action_stop(self, jail:str, action: str):
        """gets the stop command for the action <ACT> for <JAIL>"""
        return self.__request(["get", jail, "actionstop", action])

    def jail_get_action_check(self, jail:str, action: str):
        """gets the check command for the action <ACT> for <JAIL>"""
        return self.__request(["get", jail, "actioncheck", action])

    def jail_get_action_ban(self, jail:str, action: str):
        """gets the ban command for the action <ACT> for <JAIL>"""
        return self.__request(["get", jail, "actionban", action])

    def jail_get_action_unban(self, jail:str, action: str):
        """gets the unban command for the action <ACT> for <JAIL>"""
        return self.__request(["get", jail, "actionunban", action])

    def jail_get_action_timeout(self, jail:str, action: str):
        """gets the command timeout in seconds for the action <ACT> for <JAIL>"""
        return self.__request(["get", jail, "actiontimeout", action])

    # GENERAL ACTION CONFIGURATION
    def jail_get_action_properties(self, jail:str, action: str, property: str):
        """gets a list of properties for the action <ACT> for <JAIL>"""
        return self.__request(["get", jail, "action", action, property])
    
    def jail_get_action_methods(self, jail:str, action: str):
        """gets a list of methods for the action <ACT> for <JAIL>"""
        return self.__request(["get", jail, "action", action])
    
    def jail_get_action_property(self, jail:str, action: str, property: str):
        """gets the value of <PROPERTY> for the action <ACT> for <JAIL>"""
        return self.__request(["get", jail, "action", action, property])
