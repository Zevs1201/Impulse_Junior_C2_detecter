# Автоматическое Обнаружение C2 Траффика

Этот скрипт предназначен для автоматического обнаружения потенциального Command and Control (C2) траффика в сетевых логах с использованием данных Zeek.

## Функциональность

Скрипт анализирует различные типы сетевых соединений, включая HTTP, DNS, SSH, и SMB, для выявления подозрительной активности, такой как:
- Перекрывающиеся и смежные соединения
- Интересные соединения на необычных портах
- Потенциальная DGA активность в DNS
- Подозрительные UDP соединения
- Аномалии в HTTP траффике и сертификатах
- Подозрительные передачи файлов через SSH и SMB


## Установка Зависимостей
 Установка анализатора траффика zeek
```
echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_22.04/ /' | sudo tee /etc/apt/sources.list.d/security:zeek.list
curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_22.04/Release.key | gpg --dearmor | sudo tee /etc/apt/trusted.gpg.d/security_zeek.gpg > /dev/null
sudo apt update
sudo apt install zeek-6.0 
```
Установка необходимых библиотек
```
sudo apt-get install cmake make gcc g++ flex libfl-dev bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev
sudo pip3 install threading
sudo pip3 install mitmproxy
sudo pip3 install asyncio
sudo pip3 install urllib3
sudo pip3 install OTXv2
sudo pip3 install Pandas
```

## Использование
1. 
2. Подготовить лог-файлы Zeek в соответствующем формате.
3. Указать пути к этим файлам в скрипте.

Запустите скрипт командой:


