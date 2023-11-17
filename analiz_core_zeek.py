import pandas as pd
from io import StringIO
import subprocess

def read_zeek_log_with_zeekcut(file_path, columns):
    zeek_cut_command = ['zeek-cut'] + columns
    with open(file_path, 'r') as file:
        process = subprocess.Popen(zeek_cut_command, stdin=file, stdout=subprocess.PIPE)
        output, error = process.communicate()
        if error:
            raise Exception(f"Error in zeek-cut command: {error}")
        data = StringIO(output.decode('utf-8'))
        return pd.read_csv(data, sep='\t', names=columns)

def find_overlapping_connections(data):
    return data[data.duplicated(subset=['id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p'], keep=False)]

def find_adjacent_connections(data, time_window=60):
    data['timestamp'] = pd.to_datetime(data['ts'], unit='s')
    return data[data['timestamp'].diff().abs().dt.seconds <= time_window]

def find_interesting_connections(data, unusual_ports=[12345, 54321]):
    return data[data['id.orig_p'].isin(unusual_ports) | data['id.resp_p'].isin(unusual_ports)]

def detect_dga_activity(dns_data, nxdomain_threshold=10):
    grouped_data = dns_data[dns_data['rcode'] == 'NXDOMAIN'].groupby('id.orig_h').size().reset_index(name='nxdomain_count')
    return grouped_data[grouped_data['nxdomain_count'] > nxdomain_threshold]

def detect_suspicious_udp_connections(data):
    filtered_data = data[(data['service'].isna()) & (data['local_orig'] == True) & (data['local_resp'] == False)]
    grouped_data = filtered_data.groupby(['id.orig_h', 'id.resp_h', 'id.resp_p']).size().reset_index(name='connection_count')
    return grouped_data

def find_suspicious_http_traffic(http_data, x509_data):
    suspicious_http = http_data[(http_data['user_agent'].isna()) | (http_data['host'].isna())]
    suspicious_certs = x509_data[(x509_data['certificate.subject'].str.contains('obama@us.com')) | 
                                 (x509_data['certificate.issuer'].str.contains('obama@us.com'))]
    return suspicious_http, suspicious_certs


def detect_large_file_transfers_ssh(ssh_data):
    return ssh_data[ssh_data['inferences'].str.contains('LFU|LFD')]

def detect_suspicious_smb_activity(smb_data):
    suspicious_activity = smb_data[(smb_data['path'].str.contains('C$|ADMIN$')) & 
                                   (smb_data['action'] == 'SMB::FILE_OPEN')]
    return suspicious_activity
def display_potential_c2_traffic_ips(dataframes):
    with open('ips.txt', 'a') as file:
        for _, df in dataframes.items():
            if not df.empty:
                unique_ips = set(df['id.orig_h']).union(df['id.resp_h'])
                for ip in unique_ips:
                    file.write(f"{ip}\n")


# Главная функция
def main():
    # Определение колонок для каждого лог-файла
    conn_columns = ['id.orig_h', 'id.resp_h', 'id.orig_p', 'id.resp_p', 'ts', 'service', 'local_orig', 'local_resp']
    dns_columns = ['id.orig_h', 'rcode']
    http_columns = ['host', 'user_agent']
    x509_columns = ['certificate.subject', 'certificate.issuer']
    ssh_columns = ['inferences']
    smb_columns = ['path', 'action']

    # Чтение данных
    conn_data = read_zeek_log_with_zeekcut('conn.log', conn_columns)
    dns_data = read_zeek_log_with_zeekcut('dns.log', dns_columns)
    http_data = read_zeek_log_with_zeekcut('http.log', http_columns)
    x509_data = read_zeek_log_with_zeekcut('x509.log', x509_columns)
    # ssh_data = read_zeek_log_with_zeekcut('/opt/zeek/logs/files.log', ssh_columns)
    # smb_data = read_zeek_log_with_zeekcut('/usr/local/zeek/logs/current/files.log', smb_columns)
    # if smb_data:
    #     detect_suspicious_smb_activity_activity = detect_suspicious_smb_activity(smb_data)
    # else:
    #     detect_suspicious_smb_activity_activity = None

    # Вывод результатов
    analysis_results = {
        #"Перекрывающиеся соединения": overlapping,
        #"Смежные соединения": adjacent,
        "Интересные соединения": interesting,
        "Потенциальная DGA активность": dga_activity,
        "Подозрительные UDP соединения": suspicious_udp,
        "Подозрительный HTTP трафик": suspicious_http,
        "Подозрительные сертификаты": suspicious_certs,
        # x509"Подозрительные передачи файлов через SSH": suspicious_ssh_transfers,
        #"Подозрительная SMB активность": detect_suspicious_smb_activity
    }
    display_potential_c2_traffic_ips(analysis_results)

    #print("\nПодозрительная SMB активность:", suspicious_smb_activity)

if __name__ == "__main__":
    main()