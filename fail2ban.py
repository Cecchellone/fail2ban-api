import socket
import pickle

# from typing import Any

END_COMMAND = b"<F2B_END_COMMAND>"


class fail2ban:
    sock: socket.socket
    address: str

    def __init__(self, address: str):
        self.address = address
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

    def __request(self, input: str):
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)

        try:
            sock.connect(self.address)
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

            buf = buf[:-len(END_COMMAND)]

            fail2ban_output = pickle.loads(buf)

            if isinstance(fail2ban_output, tuple):
                fail2ban_output = fail2ban_output[1]
                if isinstance(fail2ban_output, tuple):
                    call = fail2ban_output[0]
                    if isinstance(call, tuple):
                        raise Exception(call[0] + ": " + call[1])

            return fail2ban.__tuple_to_dict(fail2ban_output)
        finally:
            sock.close()

    @staticmethod
    def __tuple_to_dict(object) -> dict[str]:
        if isinstance(object, list) and all([
                isinstance(t, tuple) and len(t) == 2 and isinstance(t[0], str)
                for t in object
        ]):
            ret: dict[str] = {}
            for key, value in object:
                try:
                    value = fail2ban.__tuple_to_dict(value)
                except Exception as e:
                    pass
                ret[key] = value
            return ret
        else:
            raise Exception("Invalid input")

    def get_jails(self) -> list[str]:
        result = self.__request(["status"])
        return result.get("Status for the jail", "").split(", ")

    def get_status(self, jail: str) -> dict[str, str]:
        result = self.__request(["status", jail])
        return result

    def ban(self, jail: str, ip: str) -> int:
        return self.__request(["set", jail, "banip", ip], )

    def unban(self, jail: str, ip: str) -> int:
        return self.__request(["set", jail, "unbanip", ip], )
