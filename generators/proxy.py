"""Nginx access log generators — noise and attack scenarios."""
import random
from datetime import datetime
from .config import (LEGIT_IPS, USER_AGENTS, ATTACKER_USER_AGENTS, NORMAL_PATHS,
                     NORMAL_404_PATHS, REFERERS, ATTACKER_IP_POOL,
                     pick, pick_n, rand_between, get_attacker_ips, format_nginx_log_line)
from .pages import get_lfi_payloads
from .cache import get_webshell_commands, get_shell_paths, get_shell_params


def generate_nginx_noise(count, start_time, end_time):
    lines = []
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())

    session_count = max(1, count // 8)
    generated = 0

    for _ in range(session_count):
        if generated >= count:
            break
        session_ip = pick(LEGIT_IPS)
        session_ua = pick(USER_AGENTS)
        session_start = random.randint(start_ts, max(start_ts, end_ts - 300))
        requests_in_session = random.randint(3, 15)
        current_ts = session_start

        for _ in range(requests_in_session):
            if generated >= count:
                break
            if random.randint(1, 100) <= 5:
                path_entry = pick(NORMAL_404_PATHS)
            else:
                path_entry = pick(NORMAL_PATHS)

            method, path, status, size_range = path_entry
            size = size_range[0] if size_range[0] == size_range[1] else rand_between(*size_range)
            referer = pick(REFERERS)
            rt = random.randint(1, 3000) / 1000
            ts = datetime.fromtimestamp(current_ts)

            lines.append({
                'timestamp': ts,
                'line': format_nginx_log_line(session_ip, ts, method, path, 'HTTP/1.1',
                                              status, size, referer, session_ua, rt),
            })
            current_ts += random.randint(500, 30000) / 1000
            generated += 1

    return lines


def generate_nginx_lfi(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'LFI (Local File Inclusion)',
        'vector': '/page.php?file=',
        'attacker_ips': [],
        'targeted_files': [],
    }

    attacker_ips = get_attacker_ips(overrides, attacker_count)
    payloads = get_lfi_payloads(difficulty)
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    answers['attacker_ips'] = attacker_ips

    for ip in attacker_ips:
        ua = pick(ATTACKER_USER_AGENTS)
        attack_start = random.randint(
            start_ts + int((end_ts - start_ts) * 0.2),
            int(start_ts + (end_ts - start_ts) * 0.6)
        )
        current_ts = attack_start

        selected = list(payloads)
        random.shuffle(selected)
        counts = {'easy': (8, 15), 'medium': (15, 30), 'hard': (25, len(selected))}
        lo, hi = counts.get(difficulty, (15, 30))
        selected = selected[:random.randint(lo, min(hi, len(selected)))]

        for payload, status in selected:
            path = f'/page.php?file={payload}'
            if payload not in answers['targeted_files']:
                answers['targeted_files'].append(payload)

            size = rand_between(128, 4096) if status == 200 else rand_between(256, 512)
            ts = datetime.fromtimestamp(current_ts)
            lines.append({
                'timestamp': ts,
                'line': format_nginx_log_line(ip, ts, 'GET', path, 'HTTP/1.1',
                                              status, size, '-', ua,
                                              random.randint(1, 500) / 1000),
            })
            current_ts += random.randint(1, 2) if random.randint(1, 10) <= 3 else random.randint(3, 8)

    return {'lines': lines, 'answers': answers}


def generate_nginx_bruteforce(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'HTTP Bruteforce',
        'target': '/account/login.php',
        'attacker_ips': [],
        'total_attempts_per_ip': {},
        'success': [],
    }

    attacker_ips = get_attacker_ips(overrides, attacker_count)
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    answers['attacker_ips'] = attacker_ips

    attempt_ranges = {'easy': (50, 120), 'medium': (30, 80), 'hard': (15, 40)}
    delay_ranges = {'easy': (1, 3), 'medium': (2, 8), 'hard': (5, 30)}
    att_lo, att_hi = attempt_ranges.get(difficulty, (30, 80))
    del_lo, del_hi = delay_ranges.get(difficulty, (2, 8))

    for ip in attacker_ips:
        ua = pick(ATTACKER_USER_AGENTS)
        attempts = random.randint(att_lo, att_hi)
        answers['total_attempts_per_ip'][ip] = attempts
        attack_start = random.randint(start_ts, start_ts + int((end_ts - start_ts) * 0.7))
        current_ts = attack_start
        success_attempt = random.randint(int(attempts * 0.7), attempts - 1)

        for a in range(attempts):
            is_success = (a == success_attempt)
            status = 302 if is_success else 200
            size = 0 if is_success else rand_between(1800, 2400)
            ts = datetime.fromtimestamp(current_ts)

            lines.append({
                'timestamp': ts,
                'line': format_nginx_log_line(ip, ts, 'POST', '/account/login.php', 'HTTP/1.1',
                                              status, size,
                                              'https://brightmall.local/account/login.php', ua,
                                              random.randint(50, 2000) / 1000),
            })

            if is_success:
                answers['success'].append({'ip': ip, 'attempt_number': a + 1})
            current_ts += random.randint(del_lo, del_hi)

    return {'lines': lines, 'answers': answers}


def generate_nginx_webshell(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'Webshell',
        'shell_paths': [],
        'attacker_ips': [],
        'commands_executed': [],
    }

    attacker_ips = get_attacker_ips(overrides, attacker_count)
    commands = get_webshell_commands(difficulty)
    shell_paths = get_shell_paths(difficulty)
    shell_params = get_shell_params(difficulty)
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    answers['attacker_ips'] = attacker_ips
    answers['shell_paths'] = shell_paths

    for ip_idx, ip in enumerate(attacker_ips):
        ua = pick(ATTACKER_USER_AGENTS)
        shell_path = shell_paths[ip_idx % len(shell_paths)]
        param = shell_params[ip_idx % len(shell_params)]
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
                'line': format_nginx_log_line(ip, ts, 'GET', path, 'HTTP/1.1',
                                              200, rand_between(128, 8192), '-', ua,
                                              random.randint(10, 5000) / 1000),
            })
            current_ts += random.randint(1, 5) if random.randint(1, 4) == 1 else random.randint(8, 45)

    answers['commands_executed'] = list(dict.fromkeys(answers['commands_executed']))
    return {'lines': lines, 'answers': answers}
