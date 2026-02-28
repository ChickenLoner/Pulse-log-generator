"""Apache access.log noise — realistic BrightMall browsing sessions."""
import random
from datetime import datetime
from .config import (LEGIT_IPS, USER_AGENTS, NORMAL_PATHS, NORMAL_404_PATHS,
                     REFERERS, HTTP_VERSIONS, pick, rand_between, format_log_line)


def generate_noise(count, start_time, end_time):
    lines = []
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())

    session_count = max(1, count // 8)
    sessions = []
    for _ in range(session_count):
        sessions.append({
            'ip': pick(LEGIT_IPS),
            'ua': pick(USER_AGENTS),
            'start': random.randint(start_ts, max(start_ts, end_ts - 300)),
            'requests': random.randint(3, 15),
        })

    generated = 0
    for session in sessions:
        if generated >= count:
            break
        current_ts = session['start']
        for _ in range(session['requests']):
            if generated >= count:
                break
            if random.randint(1, 100) <= 5:
                path_entry = pick(NORMAL_404_PATHS)
            else:
                path_entry = pick(NORMAL_PATHS)

            method, path, status, size_range = path_entry
            size = size_range[0] if size_range[0] == size_range[1] else rand_between(*size_range)

            if 'product.php?id=' in path and random.randint(1, 3) == 1:
                path = f'/product.php?id={random.randint(1, 20)}'

            referer = pick(REFERERS)
            http_ver = pick(HTTP_VERSIONS)
            ts = datetime.fromtimestamp(current_ts)

            lines.append({
                'timestamp': ts,
                'line': format_log_line(session['ip'], ts, method, path, http_ver,
                                        status, size, referer, session['ua']),
            })
            current_ts += random.randint(500, 30000) / 1000
            generated += 1

    return lines
