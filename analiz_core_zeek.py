import pandas as pd
from io import StringIO
import subprocess

# Функция для чтения Zeek лог-файлов с использованием инструмента zeek-cut
def read_zeek_log_with_zeekcut(file_path, columns):
    zeek_cut_command = ['zeek-cut'] + columns
    # Использование subprocess.Popen для запуска zeek-cut
    with subprocess.Popen(zeek_cut_command, stdin=open(file_path, 'r'), stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        output, error = process.communicate()
        # Проверка на наличие ошибок при выполнении команды
        if process.returncode != 0:
            raise Exception(f"Error in zeek-cut command: {error.decode('utf-8')}")
        # Конвертация вывода в формат DataFrame
        data = StringIO(output.decode('utf-8'))
        return pd.read_csv(data, sep='\t', names=columns)

# Функция для записи уникальных IP-адресов в файл
def write_unique_ips_to_file(filtered_data, file):
    unique_ips = set(filtered_data['id.resp_h'].dropna().unique())
    for ip in unique_ips:
        file.write(f"{ip}\n")

# Функция для нахождения соседних соединений в заданном временном окне
def find_adjacent_connections(data, time_window=60):
    data['timestamp'] = pd.to_datetime(data['ts'], unit='s')
    filtered_data = data[data['timestamp'].diff().abs().dt.seconds <= time_window]
    write_unique_ips_to_file(filtered_data, open('ips.txt', 'a'))

# Функция для обнаружения DGA активности в DNS данных
def detect_dga_activity(dns_data, nxdomain_threshold=10):
    grouped_data = dns_data[dns_data['rcode'] == 'NXDOMAIN'].groupby('id.resp_h').size().reset_index(name='nxdomain_count')
    filtered_data = grouped_data[grouped_data['nxdomain_count'] > nxdomain_threshold]
    write_unique_ips_to_file(filtered_data, open('ips.txt', 'a'))

# Функция для обнаружения подозрительных UDP соединений
def detect_suspicious_udp_connections(data):
    filtered_data = data[(data['service'].isna()) & (data['local_orig'] == True) & (data['local_resp'] == False)]
    write_unique_ips_to_file(filtered_data, open('ips.txt', 'a'))

# Функция для обнаружения подозрительного HTTP трафика и сертификатов
def find_suspicious_http_traffic(http_data, x509_data):
    suspicious_http = http_data[(http_data['user_agent'].isna()) | (http_data['host'].isna())]
    write_unique_ips_to_file(suspicious_http, open('ips.txt', 'a'))
    suspicious_certs = x509_data[(x509_data['certificate.subject'].str.contains('obama@us.com')) | (x509_data['certificate.issuer'].str.contains('obama@us.com'))]
    write_unique_ips_to_file(suspicious_certs, open('ips.txt', 'a'))

# Функция для обнаружения крупных передач файлов через SSH
def detect_large_file_transfers_ssh(ssh_data):
    filtered_data = ssh_data[ssh_data['inferences'].str.contains('LFU|LFD')]
    write_unique_ips_to_file(filtered_data, open('ips.txt', 'a'))

# Функция для обнаружения подозрительной SMB активности
def detect_suspicious_smb_activity(smb_data):
    suspicious_activity = smb_data[(smb_data['path'].str.contains('C$|ADMIN$')) & (smb_data['action'] == 'SMB::FILE_OPEN')]
    write_unique_ips_to_file(suspicious_activity, open('ips.txt', 'a'))

# Главная функция для инициализации и вызова функций обработки данных
def main():
    # Определение колонок для различных типов лог-файлов
    conn_columns = ['id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p', 'ts', 'service', 'local_orig', 'local_resp']
    dns_columns = ['id.orig_h', 'rcode', 'id.resp_h']
    http_columns = ['host', 'user_agent', 'id.resp_h']
    x509_columns = ['certificate.subject', 'certificate.issuer', 'id.resp_h']
    ssh_columns = ['inferences', 'id.resp_h']
    smb_columns = ['path', 'action', 'id.resp_h']

    # Чтение данных из соответствующих лог-файлов
    conn_data = read_zeek_log_with_zeekcut('conn.log', conn_columns)
    dns_data = read_zeek_log_with_zeekcut('dns.log', dns_columns)
    http_data = read_zeek_log_with_zeekcut('http.log', http_columns)
    x509_data = read_zeek_log_with_zeekcut('x509.log', x509_columns)

    # Вызов функций обработки данных
    find_adjacent_connections(conn_data)
    detect_dga_activity(dns_data)
    detect_suspicious_udp_connections(conn_data)
    find_suspicious_http_traffic(http_data, x509_data)

# Запуск главной функции при выполнении скрипта
if __name__ == "__main__":
    main()
