import socket
import sys
import datetime
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

MAX_THREADS = 100

# Banner-based protocol signatures (checked first — most accurate)
BANNER_SIGNATURES = [
    ("SSH",        ["SSH-"]),
    ("FTP",        ["220", "FTP", "FileZilla", "ProFTPD", "vsftpd", "Pure-FTPd"]),
    ("SMTP",       ["220", "ESMTP", "Postfix", "Sendmail", "Exchange", "SMTP"]),
    ("POP3",       ["+OK"]),
    ("IMAP",       ["* OK", "IMAP"]),
    ("HTTP",       ["HTTP/", "200 OK", "301 Moved", "302 Found", "400 Bad Request", "404 Not Found"]),
    ("RDP",        ["\x03\x00"]),
    ("MySQL",      ["mysql", "MariaDB", "\x00\x00\x00"]),
    ("Redis",      ["-ERR", "+PONG", "*1\r\n"]),
    ("MongoDB",    ["MongoDB", "ismaster"]),
    ("VNC",        ["RFB"]),
    ("TELNET",     ["\xff\xfd", "\xff\xfb"]),
    ("SMB",        ["\xff\x53\x4d\x42", "\xfeSMB"]),
    ("DNS",        ["\x00\x00\x84\x00"]),
    ("HTTPS",      ["SSL", "TLS", "\x16\x03"]),
]

# Port-based fallback (when banner is empty or unrecognized)
PORT_PROTOCOLS = {
    20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "TELNET",
    25: "SMTP", 53: "DNS", 67: "DHCP", 68: "DHCP",
    69: "TFTP", 80: "HTTP", 88: "Kerberos", 110: "POP3",
    111: "RPC", 119: "NNTP", 123: "NTP", 135: "MSRPC",
    137: "NetBIOS", 138: "NetBIOS", 139: "NetBIOS", 143: "IMAP",
    161: "SNMP", 194: "IRC", 389: "LDAP", 443: "HTTPS",
    445: "SMB", 465: "SMTPS", 514: "Syslog", 587: "SMTP",
    636: "LDAPS", 993: "IMAPS", 995: "POP3S", 1080: "SOCKS",
    1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
    3306: "MySQL", 3389: "RDP", 4444: "Metasploit", 5432: "PostgreSQL",
    5900: "VNC", 5985: "WinRM", 6379: "Redis", 6667: "IRC",
    8080: "HTTP", 8443: "HTTPS", 8888: "HTTP", 9200: "Elasticsearch",
    27017: "MongoDB", 27018: "MongoDB",
}

def print_banner():
    banner = """
   ==============================
        Open Port Scanner
    ==============================
    """
    print(banner)
    print("OPEN PORT SCANNER")
    print("FOUR CHAMPS")
    print("=" * 60)

def get_service_name(port):
    try:
        return socket.getservbyport(port, 'tcp')
    except Exception:
        return "unknown"

def detect_protocol(port, banner):
    # Try banner-based detection first
    if banner:
        for protocol, signatures in BANNER_SIGNATURES:
            for sig in signatures:
                if sig.lower() in banner.lower():
                    return protocol
    # Fall back to port-based lookup
    return PORT_PROTOCOLS.get(port, "unknown")

def grab_banner(ip, port, timeout=1.5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, port))

        probes = {
            80:   b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
            8080: b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
            8443: b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
            443:  b"GET / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n",
            21:   b"",
            22:   b"",
            25:   b"",
            110:  b"",
            143:  b"",
            6379: b"PING\r\n",
        }
        probe = probes.get(port, b"\r\n")
        if probe:
            s.send(probe)

        banner = s.recv(1024).decode(errors='ignore').strip()
        s.close()
        return banner.split('\n')[0][:100] if banner else None
    except Exception:
        return None

def scan_port(ip, port):
    try:
        tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        tcp.settimeout(0.5)
        result = tcp.connect_ex((ip, port))
        tcp.close()
        if result == 0:
            service  = get_service_name(port)
            banner   = grab_banner(ip, port)
            protocol = detect_protocol(port, banner)
            return {'port': port, 'service': service, 'protocol': protocol, 'banner': banner}
    except Exception:
        pass
    return None

def tcp_scan(ip, startPort, endPort):
    open_ports = []
    with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
        futures = {executor.submit(scan_port, ip, port): port for port in range(startPort, endPort + 1)}
        for future in as_completed(futures):
            result = future.result()
            if result:
                open_ports.append(result)

    open_ports.sort(key=lambda x: x['port'])
    return open_ports

def print_results(ip, results):
    if results:
        print(f"\nOpen Ports on {ip}:")
        print("-" * 75)
        print(f"{'Port':<8} {'Protocol':<12} {'Service':<18} {'Banner'}")
        print("-" * 75)
        for entry in results:
            banner_str = entry['banner'] if entry['banner'] else ""
            print(f"{entry['port']:<8} {entry['protocol']:<12} {entry['service']:<18} {banner_str}")
        print("-" * 75)
    else:
        print(f"No open ports found on {ip} in the specified range.")

def scanHost(ip, startPort, endPort):
    print(f'[*] Starting TCP port scan on host {ip} (threaded)')
    results = tcp_scan(ip, startPort, endPort)
    print_results(ip, results)
    print(f'[+] TCP scan on host {ip} complete\n')
    return results

def scanRange(network, startPort, endPort):
    print(f'[*] Starting TCP port scan on network {network}.0 (threaded)')
    all_results = {}
    for host in range(1, 255):
        ip = network + '.' + str(host)
        results = tcp_scan(ip, startPort, endPort)
        if results:
            all_results[ip] = results
            print_results(ip, results)
    print(f'[+] TCP scan on network {network}.0 complete\n')
    return all_results

def generate_report(scan_type, target, startPort, endPort, results, duration):
    timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    report_name = f"scan_report_{timestamp}.txt"
    report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), report_name)

    lines = []
    lines.append("=" * 75)
    lines.append("              OPEN PORT SCANNER - SCAN REPORT")
    lines.append("=" * 75)
    lines.append(f"Date/Time   : {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Scan Type   : {scan_type}")
    lines.append(f"Target      : {target}")
    lines.append(f"Port Range  : {startPort} - {endPort}")
    lines.append(f"Duration    : {duration:.2f} seconds")
    lines.append("=" * 75)

    def write_port_table(port_list):
        lines.append(f"{'Port':<8} {'Protocol':<12} {'Service':<18} {'Banner'}")
        lines.append("-" * 75)
        for entry in port_list:
            banner_str = entry['banner'] if entry['banner'] else "N/A"
            lines.append(f"{entry['port']:<8} {entry['protocol']:<12} {entry['service']:<18} {banner_str}")

    if scan_type == "Host Scan":
        if results:
            lines.append(f"\nOpen Ports on {target}:\n")
            write_port_table(results)
        else:
            lines.append(f"\nNo open ports found on {target}.")
    else:
        if results:
            for ip, port_list in results.items():
                lines.append(f"\nOpen Ports on {ip}:\n")
                write_port_table(port_list)
                lines.append("")
        else:
            lines.append(f"\nNo open ports found on network {target}.")

    lines.append("\n" + "=" * 75)
    lines.append("                       END OF REPORT")
    lines.append("=" * 75)

    with open(report_path, 'w') as f:
        f.write('\n'.join(lines))

    print(f"\n[+] Report saved to: {report_path}")

def main():
    print_banner()

    print("Select scan type:")
    print("  1. Single Host")
    print("  2. Network Range (/24)")
    choice = input("Choice (1/2): ").strip()

    if choice == '2':
        target = input("NETWORK (e.g. 192.168.1): ").strip()
    else:
        target = input("IP ADDRESS: ").strip()

    while True:
        try:
            startPort = int(input("START PORT: "))
            endPort   = int(input("END PORT: "))
            if not (1 <= startPort <= 65535 and 1 <= endPort <= 65535):
                print("Ports must be between 1 and 65535.")
                continue
            if startPort > endPort:
                print("Start port must be less than or equal to end port.")
                continue
            break
        except ValueError:
            print("Please enter valid integer port numbers.")

    start_time = datetime.datetime.now()

    if choice == '2':
        results = scanRange(target, startPort, endPort)
        duration = (datetime.datetime.now() - start_time).total_seconds()
        generate_report("Network Scan", target, startPort, endPort, results, duration)
    else:
        results = scanHost(target, startPort, endPort)
        duration = (datetime.datetime.now() - start_time).total_seconds()
        generate_report("Host Scan", target, startPort, endPort, results, duration)

if __name__ == "__main__":
    main()
    input("\nPress any key to close")
