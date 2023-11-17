import asyncio
import sys
import time
from mitmproxy import options, http
from mitmproxy.tools import dump

# Initial blacklist of IPs
BLACKLIST_IPS = []

def add_to_blacklist(ip_address):
        txt_zeek = open('/home/ivan/Документы/КибХак/mai/ips.txt', 'r')
        while True:
            ip = txt_zeek.readline()
            if not ip:
                break
        txt_zeek.close()
        time.sleep(60)  



def ban_ip(flow: http.HTTPFlow):
    """ Block the request if the IP is in the blacklist. """
    flow.response = http.Response.make(
        200,
        b"Access Denied: Your IP is blacklisted.",
        {"Content-Type": "text/plain"}
    )


class RequestLogger:    
    def request(self, flow: http.HTTPFlow) -> None:
        if flow.client_conn.ip_address[0] in BLACKLIST_IPS:
            ban_ip(flow)
        else:
            print(flow.response)
    


async def start_proxy(host, port):
    opts = options.Options(listen_host=host, listen_port=port)

    master = dump.DumpMaster(
        opts,
        with_termlog=False,
        with_dumper=False,
    )
    master.addons.add(RequestLogger())

    await master.run()
    return master


def start():
    host = "127.0.0.1"
    port = 9980
    print("Proxy start in " + host +":"+str(port))
    asyncio.run(start_proxy(host, port))

    
