import os
import platform
import subprocess
import socket
import ssl
import requests
import dns.resolver
import dns.query
import dns.message
import sys
import itertools
import threading
import time

def get_network_interfaces():
    os_name = platform.system().lower()
    if os_name == "windows":
        result = subprocess.run(['netsh', 'interface', 'show', 'interface'], capture_output=True, text=True)
        interfaces = [line.split()[0] for line in result.stdout.splitlines() if 'Connected' in line]
    elif os_name == "darwin" or os_name == "linux":
        result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
        interfaces = [line.split(':')[1].strip() for line in result.stdout.splitlines() if ':' in line]
    else:
        raise NotImplementedError(f"OS '{os_name}' is not supported")
    return interfaces

def set_dns_servers(dns_servers, interfaces):
    os_name = platform.system().lower()
    if os_name == "windows":
        for interface in interfaces:
            for dns in dns_servers:
                os.system(f'netsh interface ip set dns name="{interface}" source=static addr={dns} register=primary')
                os.system(f'netsh interface ip add dns name="{interface}" addr={dns} index=2')
    elif os_name == "darwin" or os_name == "linux":
        resolv_conf = "/etc/resolv.conf"
        with open(resolv_conf, 'w') as f:
            for dns in dns_servers:
                f.write(f"nameserver {dns}\n")
    else:
        raise NotImplementedError(f"OS '{os_name}' is not supported")

def check_dns_settings():
    try:
        response = requests.get('https://www.google.com', timeout=5)
        if response.status_code == 200:
            print("DNS settings are working correctly.")
        else:
            print("DNS settings may not be working correctly.")
    except requests.exceptions.RequestException as e:
        print(f"DNS settings are not working correctly: {e}")

def resolve_host_over_tls(host):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ['1.1.1.1', '1.0.0.1']  
    request = dns.message.make_query(host, dns.rdatatype.A)
    response = dns.query.tls(request, '1.1.1.1', ssl_context=ssl.create_default_context(), server_hostname='cloudflare-dns.com')
    answer = response.answer[0]
    for record in answer:
        if record.rdtype == dns.rdatatype.A:
            return record.address
    raise Exception('No A record found')

def get_ip_addresses(host):
    try:
        ip_addresses = socket.gethostbyname_ex(host)[2]
        return ip_addresses
    except socket.error as e:
        print(f'An error occurred: {e}')
        return []

def fetch_youtube_via_ip(ip):
    url = f'http://{ip}'
    headers = {'Host': 'www.youtube.com'}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            print(f"Successfully fetched YouTube homepage using IP {ip}.")
        else:
            print(f"Failed to fetch YouTube homepage using IP {ip}.")
    except requests.exceptions.RequestException as e:
        print(f'An error occurred: {e}')

def animate():
    for c in itertools.cycle(['|', '/', '-', '\\']):
        if done:
            break
        sys.stdout.write('\rLoading ' + c)
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write('\rDone!     \n')

def main():
    global done
    done = False
    animation_thread = threading.Thread(target=animate)
    animation_thread.start()
    
    dns_servers = ["1.1.1.1", "1.0.0.1"]
    interfaces = get_network_interfaces()
    set_dns_servers(dns_servers, interfaces)
    print("\nDNS servers updated successfully.")
    
    check_dns_settings()
    
    host = 'www.youtube.com'
    try:
        ip = resolve_host_over_tls(host)
        print(f'The IP address of {host} is {ip}')
    except Exception as e:
        print(f'DNS over TLS failed: {e}')
    
    try:
        ips = get_ip_addresses(host)
        if ips:
            for ip in ips:
                fetch_youtube_via_ip(ip)
    except Exception as e:
        print(f'Fetching via IPs failed: {e}')
    
    done = True
    animation_thread.join()

if __name__ == "__main__":
    main()
