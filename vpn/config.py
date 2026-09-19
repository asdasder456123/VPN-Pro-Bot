import os

WG_INTERFACE = os.getenv("WG_INTERFACE", "wg0")
WG_SERVER_ADDRESS = os.getenv("WG_SERVER_ADDRESS", "10.66.0.1/24")
WG_NETWORK = os.getenv("WG_NETWORK", "10.66.0.0/24")
WG_SERVER_PUBLIC_KEY = os.getenv("WG_SERVER_PUBLIC_KEY", "")
WG_ENDPOINT = os.getenv("WG_ENDPOINT", "")
WG_DNS = os.getenv("WG_DNS", "1.1.1.1")
WG_CLIENT_DIR = os.getenv("WG_CLIENT_DIR", "vpn/clients")
