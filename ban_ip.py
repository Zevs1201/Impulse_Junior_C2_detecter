from threading import Thread
from Proxy import start
from parsing_ip_anal import update_server_list
from parsing_ip_anal import PRIHOD_OT_ZEEK

ZEEK_List = Thread(target=PRIHOD_OT_ZEEK)
update_thread = Thread(target=update_server_list)
proxy_work= Thread(target=start)

update_thread.start()
ZEEK_List.start()
proxy_work.start()