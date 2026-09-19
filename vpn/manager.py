from pathlib import Path
import ipaddress
import json
import subprocess

from .config import (
    WG_INTERFACE,
    WG_NETWORK,
    WG_SERVER_ADDRESS,
    WG_SERVER_PUBLIC_KEY,
    WG_ENDPOINT,
    WG_DNS,
    WG_CLIENT_DIR,
)


CLIENTS_FILE = Path("vpn/clients.json")


class WireGuardManager:
    def __init__(self):
        self.client_dir = Path(WG_CLIENT_DIR)
        self.client_dir.mkdir(parents=True, exist_ok=True)

        self.network = ipaddress.ip_network(WG_NETWORK)

        self.clients_file = CLIENTS_FILE
        self.clients_file.parent.mkdir(parents=True, exist_ok=True)

        if not self.clients_file.exists():
            self.clients_file.write_text("{}\n", encoding="utf-8")

    def run(self, *args):
        return subprocess.run(
            args,
            check=True,
            text=True,
            capture_output=True,
        )

    def load_clients(self):
        try:
            data = json.loads(
                self.clients_file.read_text(encoding="utf-8")
            )
        except (OSError, json.JSONDecodeError):
            return {}

        return data if isinstance(data, dict) else {}

    def save_clients(self, clients):
        temp = self.clients_file.with_suffix(".tmp")

        temp.write_text(
            json.dumps(
                clients,
                indent=2,
                ensure_ascii=False,
            ) + "\n",
            encoding="utf-8",
        )

        temp.replace(self.clients_file)

    def generate_keys(self):
        private = self.run("wg", "genkey").stdout.strip()

        public = subprocess.run(
            ["wg", "pubkey"],
            input=private,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()

        return private, public

    def next_address(self):
        clients = self.load_clients()

        used = set()

        for client in clients.values():
            address = client.get("address")

            if not address:
                continue

            try:
                used.add(ipaddress.ip_interface(address).ip)
            except ValueError:
                continue

        server_ip = ipaddress.ip_interface(
            WG_SERVER_ADDRESS
        ).ip

        for host in self.network.hosts():
            if host == server_ip:
                continue

            if host not in used:
                return f"{host}/32"

        raise RuntimeError(
            "No free WireGuard client IP addresses"
        )

    def create_client(self, user_id: str):
        clients = self.load_clients()

        user_id = str(user_id)

        # نفس المستخدم يحصل على نفس الـVPN.
        existing = clients.get(user_id)

        if existing:
            config_path = Path(
                existing["config_path"]
            )

            if config_path.exists():
                return (
                    config_path,
                    existing["public_key"],
                    existing["address"],
                )

        if not WG_SERVER_PUBLIC_KEY:
            raise RuntimeError(
                "WG_SERVER_PUBLIC_KEY is not configured"
            )

        if not WG_ENDPOINT:
            raise RuntimeError(
                "WG_ENDPOINT is not configured"
            )

        private_key, public_key = self.generate_keys()
        address = self.next_address()

        safe_id = "".join(
            c for c in user_id
            if c.isalnum() or c in "-_"
        )[:40]

        if not safe_id:
            safe_id = "client"

        config_path = self.client_dir / f"{safe_id}.conf"

        config = (
            "[Interface]\n"
            f"PrivateKey = {private_key}\n"
            f"Address = {address}\n"
            f"DNS = {WG_DNS}\n"
            "\n"
            "[Peer]\n"
            f"PublicKey = {WG_SERVER_PUBLIC_KEY}\n"
            f"Endpoint = {WG_ENDPOINT}\n"
            "AllowedIPs = 0.0.0.0/0\n"
            "PersistentKeepalive = 25\n"
        )

        config_path.write_text(
            config,
            encoding="utf-8",
        )

        self.run(
            "wg",
            "set",
            WG_INTERFACE,
            "peer",
            public_key,
            "allowed-ips",
            address,
        )

        clients[user_id] = {
            "public_key": public_key,
            "address": address,
            "config_path": str(config_path),
        }

        self.save_clients(clients)

        return config_path, public_key, address

    def revoke_client(self, public_key: str):
        self.run(
            "wg",
            "set",
            WG_INTERFACE,
            "peer",
            public_key,
            "remove",
        )

        clients = self.load_clients()

        user_to_remove = None

        for user_id, client in clients.items():
            if client.get("public_key") == public_key:
                user_to_remove = user_id
                break

        if user_to_remove is not None:
            config_path = Path(
                clients[user_to_remove]["config_path"]
            )

            try:
                config_path.unlink()
            except FileNotFoundError:
                pass

            del clients[user_to_remove]
            self.save_clients(clients)
