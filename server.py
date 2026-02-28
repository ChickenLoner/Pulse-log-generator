"""Pulse Log Forge — Flask server."""
from flask import Flask, request, jsonify, send_from_directory
from datetime import datetime, timedelta
import json
import os
import re

from generators import traffic, pages, auth, cache, remote, proxy, service, events, netflow
from generators.service import get_iis_header
from generators.events import get_win_event_header

app = Flask(__name__, static_folder='.', static_url_path='')
TMP_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'tmp')


@app.route('/')
def index():
    return send_from_directory('.', 'index.html')


@app.route('/generate', methods=['POST'])
def generate():
    data = request.json
    if not data:
        return jsonify({'error': 'Invalid JSON'}), 400

    log_type = data.get('log_type', 'apache')
    scenarios = data.get('scenarios', [])
    noise_lines = max(50, min(5000, int(data.get('noise_lines', 500))))
    difficulty = data.get('difficulty', 'medium')
    if difficulty not in ('easy', 'medium', 'hard'):
        difficulty = 'medium'
    attacker_count = max(1, min(4, int(data.get('attacker_count', 1))))
    time_span_hours = max(1, min(48, int(data.get('time_span_hours', 6))))
    output_mode = data.get('output_mode', 'download')
    overrides = data.get('overrides', {})

    valid_types = ['apache', 'nginx', 'iis', 'ssh', 'windows', 'firewall']
    if log_type not in valid_types:
        log_type = 'apache'

    end_time = datetime.now()
    start_time = end_time - timedelta(hours=time_span_hours)

    all_lines = []
    all_answers = {}
    file_prefix = ''
    file_header = ''

    if log_type == 'apache':
        all_lines += traffic.generate_noise(noise_lines, start_time, end_time)
        if 'lfi' in scenarios:
            r = pages.generate_lfi(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['lfi'] = r['answers']
        if 'bruteforce' in scenarios:
            r = auth.generate_bruteforce(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['bruteforce'] = r['answers']
        if 'webshell' in scenarios:
            r = cache.generate_webshell(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['webshell'] = r['answers']
        file_prefix = 'access'

    elif log_type == 'nginx':
        all_lines += proxy.generate_nginx_noise(noise_lines, start_time, end_time)
        if 'lfi' in scenarios:
            r = proxy.generate_nginx_lfi(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['lfi'] = r['answers']
        if 'bruteforce' in scenarios:
            r = proxy.generate_nginx_bruteforce(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['bruteforce'] = r['answers']
        if 'webshell' in scenarios:
            r = proxy.generate_nginx_webshell(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['webshell'] = r['answers']
        file_prefix = 'nginx_access'

    elif log_type == 'iis':
        file_header = get_iis_header(start_time)
        all_lines += service.generate_iis_noise(noise_lines, start_time, end_time)
        if 'lfi' in scenarios:
            r = service.generate_iis_lfi(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['lfi'] = r['answers']
        if 'bruteforce' in scenarios:
            r = service.generate_iis_bruteforce(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['bruteforce'] = r['answers']
        if 'webshell' in scenarios:
            r = service.generate_iis_webshell(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['webshell'] = r['answers']
        file_prefix = 'u_ex' + end_time.strftime('%y%m%d')

    elif log_type == 'ssh':
        all_lines += remote.generate_ssh_noise(noise_lines, start_time, end_time)
        if 'ssh_bruteforce' in scenarios:
            r = remote.generate_ssh_bruteforce(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['ssh_bruteforce'] = r['answers']
        if 'ssh_spray' in scenarios:
            r = remote.generate_ssh_spray(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['ssh_spray'] = r['answers']
        file_prefix = 'auth'

    elif log_type == 'windows':
        file_header = get_win_event_header() + '\n'
        all_lines += events.generate_win_noise(noise_lines, start_time, end_time)
        if 'win_bruteforce' in scenarios:
            r = events.generate_win_bruteforce(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['win_bruteforce'] = r['answers']
        if 'win_postexploit' in scenarios:
            r = events.generate_win_post_exploit(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['win_postexploit'] = r['answers']
        file_prefix = 'Security'

    elif log_type == 'firewall':
        all_lines += netflow.generate_fw_noise(noise_lines, start_time, end_time)
        if 'fw_portscan' in scenarios:
            r = netflow.generate_fw_port_scan(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['fw_portscan'] = r['answers']
        if 'fw_beacon' in scenarios:
            r = netflow.generate_fw_beacon(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['fw_beacon'] = r['answers']
        if 'fw_exfil' in scenarios:
            r = netflow.generate_fw_exfil(attacker_count, difficulty, start_time, end_time, overrides)
            all_lines += r['lines']
            all_answers['fw_exfil'] = r['answers']
        file_prefix = 'firewall'

    all_lines.sort(key=lambda x: x['timestamp'])
    ext = '.csv' if log_type == 'windows' else '.log'
    log_content = file_header + '\n'.join(line['line'] for line in all_lines) + '\n'
    total_lines = len(all_lines)

    if output_mode == 'preview':
        log_lines = log_content.strip().split('\n')
        return jsonify({
            'success': True,
            'total_lines': total_lines,
            'preview_head': log_lines[:20],
            'preview_tail': log_lines[-10:],
            'answers': all_answers,
        })
    else:
        os.makedirs(TMP_DIR, exist_ok=True)
        filename = f'{file_prefix}_{end_time.strftime("%Y%m%d_%H%M%S")}{ext}'
        with open(os.path.join(TMP_DIR, filename), 'w', encoding='utf-8') as f:
            f.write(log_content)

        answer_filename = filename.replace(ext, '_answers.json')
        with open(os.path.join(TMP_DIR, answer_filename), 'w', encoding='utf-8') as f:
            json.dump(all_answers, f, indent=2, ensure_ascii=False)

        return jsonify({
            'success': True,
            'total_lines': total_lines,
            'download_url': f'/download?f={filename}',
            'answer_url': f'/download?f={answer_filename}',
            'answers': all_answers,
        })


@app.route('/download')
def download():
    filename = request.args.get('f', '')
    if not re.match(r'^[a-zA-Z0-9_.\\-]+$', filename):
        return jsonify({'error': 'Invalid filename'}), 400
    try:
        return send_from_directory(TMP_DIR, filename, as_attachment=True)
    except Exception:
        return jsonify({'error': 'File not found'}), 404


if __name__ == '__main__':
    app.run(debug=True, port=5000)
