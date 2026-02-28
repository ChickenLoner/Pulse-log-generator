"""Firewall (iptables) log generators — noise, port scan, beaconing, exfiltration."""
import random
from datetime import datetime
from .config import (FW_HOSTNAME, FW_INTERNAL_NET, FW_SERVER_IP, FW_LEGIT_PORTS,
                     FW_LEGIT_DEST_IPS, FW_C2_IPS,
                     pick, pick_n, get_override, get_attacker_ips, format_fw_log_line)


def generate_fw_noise(count, start_time, end_time):
    lines = []
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    hostname = FW_HOSTNAME
    generated = 0

    while generated < count:
        ts = random.randint(start_ts, end_ts)
        dt = datetime.fromtimestamp(ts)
        event_type = random.randint(1, 100)

        if event_type <= 50:
            src_ip = FW_INTERNAL_NET + str(random.randint(10, 250))
            dst_ip = pick(FW_LEGIT_DEST_IPS)
            dst_port = pick(FW_LEGIT_PORTS)
            src_port = random.randint(32768, 65535)
            proto = 'UDP' if (dst_port == 53 and random.randint(1, 3) == 1) else 'TCP'
            lines.append({
                'timestamp': dt,
                'line': format_fw_log_line(dt, hostname, 'ACCEPT', 'eth1', 'eth0',
                                           src_ip, dst_ip, proto, src_port, dst_port),
            })

        elif event_type <= 70:
            src_ip = pick(FW_LEGIT_DEST_IPS)
            dst_ip = FW_SERVER_IP
            dst_port = pick([80, 443])
            src_port = random.randint(32768, 65535)
            lines.append({
                'timestamp': dt,
                'line': format_fw_log_line(dt, hostname, 'ACCEPT', 'eth0', 'eth2',
                                           src_ip, dst_ip, 'TCP', src_port, dst_port),
            })

        elif event_type <= 85:
            src_ip = (f'{random.randint(1, 223)}.{random.randint(0, 255)}.'
                      f'{random.randint(0, 255)}.{random.randint(1, 254)}')
            dst_ip = FW_SERVER_IP
            dst_port = pick([23, 445, 3389, 8443, 8888, 9090, 1433, 5900, 6379, 27017])
            src_port = random.randint(32768, 65535)
            lines.append({
                'timestamp': dt,
                'line': format_fw_log_line(dt, hostname, 'DROP', 'eth0', '',
                                           src_ip, dst_ip, 'TCP', src_port, dst_port, 'SYN'),
            })

        elif event_type <= 93:
            src_ip = FW_INTERNAL_NET + str(random.randint(10, 250))
            dst_ip = pick(['8.8.8.8', '8.8.4.4', '1.1.1.1'])
            lines.append({
                'timestamp': dt,
                'line': format_fw_log_line(dt, hostname, 'ACCEPT', 'eth1', 'eth0',
                                           src_ip, dst_ip, 'UDP', random.randint(32768, 65535), 53),
            })

        else:
            src_ip = FW_INTERNAL_NET + str(random.randint(10, 250))
            dst_ip = pick(FW_LEGIT_DEST_IPS)
            lines.append({
                'timestamp': dt,
                'line': format_fw_log_line(dt, hostname, 'ACCEPT', 'eth1', 'eth0',
                                           src_ip, dst_ip, 'ICMP', 0, 0),
            })

        generated += 1

    return lines


def generate_fw_port_scan(attacker_count, difficulty, start_time, end_time, overrides=None):
    target_ip = get_override(overrides, 'fw_target_ip', FW_SERVER_IP)
    lines = []
    answers = {
        'type': 'Port Scan',
        'attacker_ips': [],
        'target_ip': target_ip,
        'ports_scanned': [],
        'scan_type': '',
    }

    attacker_ips = get_attacker_ips(overrides, attacker_count)
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    hostname = FW_HOSTNAME
    answers['attacker_ips'] = attacker_ips

    if difficulty == 'easy':
        port_ranges = list(range(1, 1025))
    elif difficulty == 'hard':
        port_ranges = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
                       1433, 1521, 2049, 3306, 3389, 5432, 5900, 5985, 6379, 8080, 8443, 9200, 27017]
    else:
        port_ranges = (list(range(1, 101)) +
                       [135, 139, 443, 445, 1433, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9090, 27017])

    if difficulty == 'hard':
        random.shuffle(port_ranges)
        answers['scan_type'] = 'Randomized stealth scan'
    else:
        answers['scan_type'] = 'Sequential SYN scan'

    delay_ranges = {'easy': (0, 1), 'medium': (1, 5), 'hard': (10, 60)}
    del_lo, del_hi = delay_ranges.get(difficulty, (1, 5))
    open_ports = [22, 80, 443, 3306]

    for ip in attacker_ips:
        attack_start = random.randint(start_ts, start_ts + int((end_ts - start_ts) * 0.3))
        current_ts = attack_start
        ports_for_ip = []

        for port in port_ranges:
            dt = datetime.fromtimestamp(current_ts)
            src_port = random.randint(32768, 65535)
            action = 'ACCEPT' if port in open_ports else 'DROP'

            lines.append({
                'timestamp': dt,
                'line': format_fw_log_line(dt, hostname, action, 'eth0',
                                           'eth2' if action == 'ACCEPT' else '',
                                           ip, target_ip, 'TCP', src_port, port, 'SYN'),
            })
            ports_for_ip.append(port)

            delay = random.randint(del_lo, del_hi)
            if difficulty == 'easy' and random.randint(1, 5) == 1:
                delay = 0
            current_ts += delay

        answers['ports_scanned'] = ports_for_ip

    return {'lines': lines, 'answers': answers}


def generate_fw_beacon(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'C2 Beaconing',
        'infected_hosts': [],
        'c2_servers': [],
        'beacon_interval_seconds': 0,
        'c2_port': 0,
    }

    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    hostname = FW_HOSTNAME

    infected_count = min(attacker_count, 3)
    infected_hosts = [FW_INTERNAL_NET + str(random.randint(10, 250)) for _ in range(infected_count)]

    c2_ip = get_override(overrides, 'fw_c2_ip', None) or pick(FW_C2_IPS)
    c2_port = int(get_override(overrides, 'fw_c2_port', 0) or 0) or pick([443, 8443, 4444, 8080, 53])

    custom_interval = int(get_override(overrides, 'fw_beacon_interval', 0) or 0)
    base_interval = custom_interval or {'easy': 60, 'medium': 120, 'hard': 300}.get(difficulty, 120)

    custom_jitter = get_override(overrides, 'fw_beacon_jitter', None)
    if custom_jitter is not None:
        jitter = int(base_interval * (int(custom_jitter) / 100))
    else:
        jitter = {'easy': 0, 'medium': int(base_interval * 0.1),
                  'hard': int(base_interval * 0.3)}.get(difficulty, int(base_interval * 0.1))

    answers['infected_hosts'] = infected_hosts
    answers['c2_servers'] = [c2_ip]
    answers['beacon_interval_seconds'] = base_interval
    answers['c2_port'] = c2_port

    for src_ip in infected_hosts:
        current_ts = start_ts + random.randint(0, base_interval)
        proto = 'UDP' if c2_port == 53 else 'TCP'

        while current_ts < end_ts:
            dt = datetime.fromtimestamp(current_ts)
            src_port = random.randint(32768, 65535)
            flags = 'SYN ACK' if proto == 'TCP' else ''

            lines.append({
                'timestamp': dt,
                'line': format_fw_log_line(dt, hostname, 'ACCEPT', 'eth1', 'eth0',
                                           src_ip, c2_ip, proto, src_port, c2_port, flags),
            })

            actual_interval = (base_interval + random.randint(-jitter, jitter)
                               if jitter > 0 else base_interval)
            current_ts += max(10, actual_interval)

    return {'lines': lines, 'answers': answers}


def generate_fw_exfil(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'Data Exfiltration',
        'source_host': '',
        'exfil_destination': '',
        'exfil_port': 0,
        'total_connections': 0,
    }

    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    hostname = FW_HOSTNAME

    infected_host = FW_INTERNAL_NET + str(random.randint(10, 250))
    exfil_dst = get_override(overrides, 'fw_exfil_ip', None) or pick(FW_C2_IPS)
    exfil_port = int(get_override(overrides, 'fw_exfil_port', 0) or 0) or pick([443, 8443, 21, 22])

    answers['source_host'] = infected_host
    answers['exfil_destination'] = exfil_dst
    answers['exfil_port'] = exfil_port

    burst_counts = {'easy': (3, 5), 'medium': (5, 10), 'hard': (10, 20)}
    blo, bhi = burst_counts.get(difficulty, (5, 10))
    burst_count = random.randint(blo, bhi)

    conn_per_burst = {'easy': (20, 50), 'medium': (10, 25), 'hard': (3, 8)}
    clo, chi = conn_per_burst.get(difficulty, (10, 25))
    connections_per_burst = random.randint(clo, chi)

    total_conns = 0

    for _ in range(burst_count):
        burst_start = random.randint(
            start_ts + int((end_ts - start_ts) * 0.4),
            max(start_ts + int((end_ts - start_ts) * 0.4) + 1, end_ts - 300)
        )
        current_ts = burst_start

        for _ in range(connections_per_burst):
            dt = datetime.fromtimestamp(current_ts)
            src_port = random.randint(32768, 65535)

            lines.append({
                'timestamp': dt,
                'line': format_fw_log_line(dt, hostname, 'ACCEPT', 'eth1', 'eth0',
                                           infected_host, exfil_dst, 'TCP', src_port, exfil_port,
                                           'SYN ACK PSH'),
            })
            current_ts += random.randint(1, 5)
            total_conns += 1

    answers['total_connections'] = total_conns
    return {'lines': lines, 'answers': answers}
