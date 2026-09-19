import asyncio
import ipaddress


async def ping_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return False

    process = await asyncio.create_subprocess_exec(
        "ping",
        "-c",
        "1",
        "-W",
        "1",
        host,
        stdout=asyncio.subprocess.DEVNULL,
        stderr=asyncio.subprocess.DEVNULL,
    )

    return await process.wait() == 0


async def scan_hosts(network: str) -> list[str]:
    try:
        net = ipaddress.ip_network(network, strict=False)
    except ValueError:
        return []

    hosts = list(net.hosts())[:254]

    results = await asyncio.gather(
        *(ping_host(str(host)) for host in hosts)
    )

    return [
        str(host)
        for host, online in zip(hosts, results)
        if online
    ]
