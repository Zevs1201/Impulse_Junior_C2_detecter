import urllib.request
import time
from OTXv2 import OTXv2
import json


from Proxy import add_to_blacklist

API_KEY_OTX = '04d8119bfe24065f8d07465d625908457eed8a8fb31347cf2fee468040f73884'

class Server:
    def __init__(self, ip_address):
        self.ip_address = ip_address



def get_pulse_details(pulse_id):
    otx = OTXv2(API_KEY_OTX)
    try:
        pulse_details = otx.get_pulse_details(pulse_id)
        return pulse_details
    except Exception as e:
        print(f"An error occurred: {e}")
        return None

def OTX():
    pulse_id = '61b72e243e746d2994b3ba54'
    pulse_details = get_pulse_details(pulse_id)

    if pulse_details:
        gol = json.dumps(pulse_details, indent=4)
        gol_dict = json.loads(gol)

        for entry in gol_dict["indicators"]:
            ip_address = entry["indicator"]
            add_to_blacklist(ip_address)
    else:
        print("Failed to retrieve pulse details.")
def update_server_list():
    while True:
        OTX()
        feodo_tracker()
        time.sleep(900)
def feodo_tracker():
    url = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"

    response = urllib.request.urlopen(url)
    data = json.loads(response.read().decode())

    temp_server_list = []

    for entry in data:
        ip_address = entry["ip_address"]

        server = Server(ip_address)
        temp_server_list.append(server)

    server_list = temp_server_list
    for server in server_list:
        add_to_blacklist(server.ip_address)
    print("Servers:")
    for server in server_list:
        print(f"IP Address: {server.ip_address}")

def PRIHOD_OT_ZEEK():
    time.sleep(300)
    while True:
        txt_zeek = open('/home/ivan/Документы/КибХак/mai/ips.txt', 'r')
        while True:
            ip = txt_zeek.readline()
            if not ip:
                break
            add_to_blacklist(ip)
        txt_zeek.close()
        time.sleep(60)



