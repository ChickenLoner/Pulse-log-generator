"""HTTP bruteforce attack scenario — credential stuffing on /account/login.php"""
import random
from datetime import datetime
from .config import (LEGIT_IPS, USER_AGENTS, ATTACKER_USER_AGENTS,
                     pick, pick_n, rand_between, get_override, get_attacker_ips,
                     format_log_line)


def generate_bruteforce(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    login_endpoint = get_override(overrides, 'brute_endpoint', '/account/login.php')
    success_code = int(get_override(overrides, 'brute_success_code', 302) or 302)

    answers = {
        'type': 'HTTP Bruteforce',
        'target': login_endpoint,
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
    rotate_ua = (difficulty == 'hard')

    for ip in attacker_ips:
        ua = pick(ATTACKER_USER_AGENTS)
        attempts = random.randint(att_lo, att_hi)
        answers['total_attempts_per_ip'][ip] = attempts

        attack_window = int((end_ts - start_ts) * 0.7)
        attack_start = random.randint(start_ts, start_ts + attack_window)
        current_ts = attack_start
        do_get_before_post = (difficulty == 'hard')
        success_attempt = random.randint(int(attempts * 0.7), attempts - 1)

        for a in range(attempts):
            if rotate_ua and random.randint(1, 5) == 1:
                ua = pick(ATTACKER_USER_AGENTS)

            if do_get_before_post and random.randint(1, 3) == 1:
                ts = datetime.fromtimestamp(current_ts)
                lines.append({
                    'timestamp': ts,
                    'line': format_log_line(ip, ts, 'GET', login_endpoint, 'HTTP/1.1',
                                            200, rand_between(1024, 2048),
                                            'https://brightmall.local/', ua),
                })
                current_ts += random.randint(1, 3)

            is_success = (a == success_attempt)
            if is_success:
                status, size = success_code, 0
                answers['success'].append({'ip': ip, 'attempt_number': a + 1})
            else:
                status, size = 200, rand_between(1800, 2400)

            ts = datetime.fromtimestamp(current_ts)
            lines.append({
                'timestamp': ts,
                'line': format_log_line(ip, ts, 'POST', login_endpoint, 'HTTP/1.1',
                                        status, size,
                                        'https://brightmall.local/account/login.php', ua),
            })

            if is_success:
                current_ts += 1
                ts2 = datetime.fromtimestamp(current_ts)
                lines.append({
                    'timestamp': ts2,
                    'line': format_log_line(ip, ts2, 'GET', '/account/profile.php', 'HTTP/1.1',
                                            200, rand_between(2048, 3072),
                                            'https://brightmall.local/account/login.php', ua),
                })
                for _ in range(random.randint(1, 3)):
                    current_ts += random.randint(5, 20)
                    ts3 = datetime.fromtimestamp(current_ts)
                    browse_path = pick(['/products.php', '/account/profile.php', '/cart.php'])
                    lines.append({
                        'timestamp': ts3,
                        'line': format_log_line(ip, ts3, 'GET', browse_path, 'HTTP/1.1',
                                                200, rand_between(2048, 8192),
                                                'https://brightmall.local/account/profile.php', ua),
                    })

            delay = random.randint(del_lo, del_hi)
            if difficulty == 'easy' and random.randint(1, 4) == 1:
                delay = 0
            current_ts += delay

    # Legitimate failed logins from normal users
    for _ in range(random.randint(2, 5)):
        legit_ip = pick(LEGIT_IPS)
        legit_ua = pick(USER_AGENTS)
        legit_time = random.randint(start_ts, end_ts - 60)
        for _ in range(random.randint(1, 2)):
            ts = datetime.fromtimestamp(legit_time)
            lines.append({
                'timestamp': ts,
                'line': format_log_line(legit_ip, ts, 'POST', login_endpoint, 'HTTP/1.1',
                                        200, rand_between(1800, 2400),
                                        'https://brightmall.local/account/login.php', legit_ua),
            })
            legit_time += random.randint(5, 20)
        ts = datetime.fromtimestamp(legit_time)
        lines.append({
            'timestamp': ts,
            'line': format_log_line(legit_ip, ts, 'POST', login_endpoint, 'HTTP/1.1',
                                    302, 0,
                                    'https://brightmall.local/account/login.php', legit_ua),
        })

    return {'lines': lines, 'answers': answers}
