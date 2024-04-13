import requests
from requests.exceptions import RequestException
from requests.auth import HTTPBasicAuth
import os
from dotenv import load_dotenv
import mysql.connector
from mysql.connector import Error

load_dotenv(dotenv_path="/home/pi/WebService/passwebservice/.env")

db_host = os.getenv('UTILITY_DB_HOST')
db_user = os.getenv('UTILITY_DB_USER_NAME')
db_password = os.getenv('UTILITY_DB_PASS')
db_name = os.getenv('UTILITY_DB_NAME')

ddns_username = os.getenv("DDNS_USER_NAME")
ddns_password = os.getenv("DDNS_PASSWORD")
ddns_hostname = os.getenv("DDNS_HOST_NAME")

ip_file_path = '/home/pi/WebService/passwebservice/utils/current_ip.txt'

def log_update(old_ip, new_ip, status, message):
    try:
        conn = mysql.connector.connect(host=db_host, database=db_name, user=db_user, password=db_password)
        if conn.is_connected():
            cursor = conn.cursor()
            sql = "INSERT INTO updates (hostname, old_ip, new_ip, status, message) VALUES (%s, %s, %s, %s, %s)"
            values = (ddns_hostname, old_ip, new_ip, status, message)
            cursor.execute(sql, values)
            conn.commit()
    except Error as e:
        print(f"Error logging to database: {e}")
    finally:
        if conn.is_connected():
            cursor.close()
            conn.close()
            
def get_public_ip():
    try:
        response = requests.get("https://api.ipify.org?format=json", timeout=10)
        response.raise_for_status()
        ip_data = response.json()
        ip = ip_data.get("ip")
        if ip:
            return ip
        else:
            raise ValueError("Can not find 'ip' key from json response.")
    except RequestException as e:
        raise RuntimeError("ERR: " + str(e))

def read_last_ip():
    try:
        with open(ip_file_path, 'r') as file:
            return file.read().strip()
    except FileNotFoundError:
        return None

def write_last_ip(ip):
    with open(ip_file_path, 'w') as file:
        file.write(ip)

def update_dns(ip):
    url = f"https://domains.google.com/nic/update"
    params = {'hostname': ddns_hostname, 'myip': ip}
    response = requests.post(url, params=params, auth=HTTPBasicAuth(ddns_username, ddns_password))
    if response.status_code == 200:
        message = "SUCCESS"
        status = response.status_code
    else:
        message = "FAILED"
        status = response.status_code
    return status, message

if __name__ == "__main__":
    current_ip = get_public_ip()
    last_ip = read_last_ip()

    if current_ip != last_ip:
        status, message = update_dns(current_ip)
        write_last_ip(current_ip)
        log_update(last_ip, current_ip, status, message)
        print(f"DNS updated to new IP: {current_ip}")
    else:
        print("IP address has not changed. No update required.")