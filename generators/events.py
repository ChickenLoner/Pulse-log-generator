"""Windows Security Event Log generators — noise, bruteforce, post-exploitation."""
import random
from datetime import datetime
from .config import (WIN_HOSTNAME, WIN_DOMAIN, WIN_LEGIT_USERS, WIN_WORKSTATIONS,
                     WIN_BRUTE_USERS, WIN_SUSPICIOUS_PROCS, WIN_NORMAL_PROCS,
                     SSH_LEGIT_IPS,
                     pick, pick_n, rand_between, get_override, get_attacker_ips,
                     format_win_event_line)


def get_win_event_header():
    return 'TimeCreated,EventID,Level,Computer,SourceName,Message'


def generate_win_noise(count, start_time, end_time):
    lines = []
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    hostname = WIN_HOSTNAME
    domain = WIN_DOMAIN
    generated = 0

    while generated < count:
        ts = random.randint(start_ts, end_ts)
        dt = datetime.fromtimestamp(ts)
        event_type = random.randint(1, 100)

        if event_type <= 35:
            user = pick(WIN_LEGIT_USERS)
            logon_type = pick([2, 3, 5, 7, 10])
            logon_type_names = {2: 'Interactive', 3: 'Network', 5: 'Service',
                                7: 'Unlock', 10: 'RemoteInteractive'}
            src_ip = pick(SSH_LEGIT_IPS) if logon_type in (3, 10) else '-'
            wks = pick(WIN_WORKSTATIONS) if logon_type == 10 else hostname
            logon_id = hex(random.randint(0x10000, 0xFFFFF))[2:].upper()
            msg = (f'An account was successfully logged on. Subject: Security ID: S-1-5-18 '
                   f'Account Name: {hostname}$ Logon Type: {logon_type} ({logon_type_names[logon_type]}) '
                   f'New Logon: Account Name: {user} Account Domain: {domain} '
                   f'Logon ID: 0x{logon_id} '
                   f'Network Information: Workstation Name: {wks} Source Network Address: {src_ip}')

            lines.append({
                'timestamp': dt,
                'line': format_win_event_line(dt, 4624, 'Information', hostname,
                                              'Microsoft-Windows-Security-Auditing', msg),
            })
            generated += 1

            if random.randint(1, 3) <= 2:
                off_ts = ts + random.randint(60, 7200)
                if off_ts <= end_ts:
                    dt2 = datetime.fromtimestamp(off_ts)
                    msg2 = (f'An account was logged off. Subject: Account Name: {user} '
                            f'Account Domain: {domain} Logon Type: {logon_type}')
                    lines.append({
                        'timestamp': dt2,
                        'line': format_win_event_line(dt2, 4634, 'Information', hostname,
                                                      'Microsoft-Windows-Security-Auditing', msg2),
                    })
                    generated += 1

        elif event_type <= 50:
            user = pick(['Administrator', 'svc_web', 'svc_sql', 'SYSTEM'])
            msg = (f'Special privileges assigned to new logon. Subject: Account Name: {user} '
                   f'Account Domain: {domain} Privileges: SeSecurityPrivilege SeBackupPrivilege '
                   f'SeRestorePrivilege SeTakeOwnershipPrivilege SeDebugPrivilege '
                   f'SeSystemEnvironmentPrivilege SeLoadDriverPrivilege SeImpersonatePrivilege')
            lines.append({
                'timestamp': dt,
                'line': format_win_event_line(dt, 4672, 'Information', hostname,
                                              'Microsoft-Windows-Security-Auditing', msg),
            })
            generated += 1

        elif event_type <= 75:
            proc = pick(WIN_NORMAL_PROCS)
            user = pick(['SYSTEM', 'LOCAL SERVICE', 'NETWORK SERVICE', pick(WIN_LEGIT_USERS)])
            proc_id = hex(random.randint(0x100, 0xFFFF))[2:].upper()
            msg = (f'A new process has been created. Creator Subject: Account Name: {user} '
                   f'Account Domain: {domain} New Process Information: '
                   f'New Process ID: 0x{proc_id} New Process Name: {proc[1]} '
                   f'Creator Process Name: C:\\Windows\\System32\\services.exe '
                   f'Process Command Line: {proc[1]} {proc[2]}')
            lines.append({
                'timestamp': dt,
                'line': format_win_event_line(dt, 4688, 'Information', hostname,
                                              'Microsoft-Windows-Security-Auditing', msg),
            })
            generated += 1

        elif event_type <= 85:
            user = pick(WIN_LEGIT_USERS)
            src_ip = pick(SSH_LEGIT_IPS)
            msg = (f'An account failed to log on. Subject: Security ID: S-1-0-0 Account Name: - '
                   f'Logon Type: 10 (RemoteInteractive) '
                   f'Account For Which Logon Failed: Account Name: {user} Account Domain: {domain} '
                   f'Failure Reason: Unknown user name or bad password. '
                   f'Status: 0xC000006D Sub Status: 0xC000006A Source Network Address: {src_ip}')
            lines.append({
                'timestamp': dt,
                'line': format_win_event_line(dt, 4625, 'Information', hostname,
                                              'Microsoft-Windows-Security-Auditing', msg),
            })
            generated += 1

        else:
            services = [
                ('Windows Update Service', 'C:\\Windows\\System32\\wuauserv.dll', 'auto start'),
                ('Background Intelligent Transfer Service', 'C:\\Windows\\System32\\qmgr.dll', 'auto start'),
                ('Windows Defender Antivirus Service',
                 'C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\MsMpEng.exe', 'auto start'),
                ('Print Spooler', 'C:\\Windows\\System32\\spoolsv.exe', 'auto start'),
            ]
            svc = pick(services)
            msg = (f'A service was installed in the system. Service Name: {svc[0]} '
                   f'Service File Name: {svc[1]} Service Type: user mode service '
                   f'Service Start Type: {svc[2]} Service Account: LocalSystem')
            lines.append({
                'timestamp': dt,
                'line': format_win_event_line(dt, 7045, 'Information', hostname, 'System', msg),
            })
            generated += 1

    return lines


def generate_win_bruteforce(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'Windows Logon Bruteforce (4625/4624)',
        'attacker_ips': [],
        'total_attempts_per_ip': {},
        'compromised_account': None,
        'success': [],
    }

    attacker_ips = get_attacker_ips(overrides, attacker_count)
    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    hostname = get_override(overrides, 'win_hostname', WIN_HOSTNAME)
    domain = get_override(overrides, 'win_domain', WIN_DOMAIN)
    answers['attacker_ips'] = attacker_ips

    attempt_ranges = {'easy': (60, 150), 'medium': (30, 80), 'hard': (15, 40)}
    delay_ranges = {'easy': (1, 3), 'medium': (3, 10), 'hard': (10, 45)}
    att_lo, att_hi = attempt_ranges.get(difficulty, (30, 80))
    del_lo, del_hi = delay_ranges.get(difficulty, (3, 10))

    for ip in attacker_ips:
        attempts = random.randint(att_lo, att_hi)
        answers['total_attempts_per_ip'][ip] = attempts
        attack_start = random.randint(start_ts, start_ts + int((end_ts - start_ts) * 0.5))
        current_ts = attack_start
        success_attempt = random.randint(int(attempts * 0.75), attempts - 1)

        logon_type = pick([3, 10])
        logon_type_name = 'RemoteInteractive' if logon_type == 10 else 'Network'

        for a in range(attempts):
            dt = datetime.fromtimestamp(current_ts)
            is_success = (a == success_attempt)
            user = pick(WIN_BRUTE_USERS)

            if is_success:
                target_user = pick(WIN_LEGIT_USERS[:5])
                logon_id = hex(random.randint(0x10000, 0xFFFFF))[2:].upper()
                msg = (f'An account was successfully logged on. Subject: Security ID: S-1-5-18 '
                       f'Account Name: {hostname}$ Logon Type: {logon_type} ({logon_type_name}) '
                       f'New Logon: Account Name: {target_user} Account Domain: {domain} '
                       f'Logon ID: 0x{logon_id} '
                       f'Network Information: Source Network Address: {ip}')
                lines.append({
                    'timestamp': dt,
                    'line': format_win_event_line(dt, 4624, 'Information', hostname,
                                                  'Microsoft-Windows-Security-Auditing', msg),
                })
                answers['compromised_account'] = target_user
                answers['success'].append({'ip': ip, 'user': target_user, 'attempt_number': a + 1})

                dt2 = datetime.fromtimestamp(current_ts + 1)
                msg2 = (f'Special privileges assigned to new logon. Subject: Account Name: {target_user} '
                        f'Account Domain: {domain} Privileges: SeSecurityPrivilege SeBackupPrivilege '
                        f'SeRestorePrivilege SeTakeOwnershipPrivilege SeDebugPrivilege')
                lines.append({
                    'timestamp': dt2,
                    'line': format_win_event_line(dt2, 4672, 'Information', hostname,
                                                  'Microsoft-Windows-Security-Auditing', msg2),
                })
            else:
                sub_status = pick(['0xC000006A', '0xC0000064', '0xC000006D'])
                msg = (f'An account failed to log on. Subject: Security ID: S-1-0-0 Account Name: - '
                       f'Logon Type: {logon_type} ({logon_type_name}) '
                       f'Account For Which Logon Failed: Account Name: {user} Account Domain: {domain} '
                       f'Failure Reason: Unknown user name or bad password. '
                       f'Status: 0xC000006D Sub Status: {sub_status} Source Network Address: {ip}')
                lines.append({
                    'timestamp': dt,
                    'line': format_win_event_line(dt, 4625, 'Information', hostname,
                                                  'Microsoft-Windows-Security-Auditing', msg),
                })

            current_ts += random.randint(del_lo, del_hi)

    return {'lines': lines, 'answers': answers}


def generate_win_post_exploit(attacker_count, difficulty, start_time, end_time, overrides=None):
    lines = []
    answers = {
        'type': 'Post-Exploitation (Process Creation / Persistence)',
        'compromised_account': None,
        'suspicious_processes': [],
        'created_users': [],
        'malicious_services': [],
    }

    start_ts = int(start_time.timestamp())
    end_ts = int(end_time.timestamp())
    hostname = get_override(overrides, 'win_hostname', WIN_HOSTNAME)
    domain = get_override(overrides, 'win_domain', WIN_DOMAIN)

    compromised_user = get_override(overrides, 'win_compromised_user', None) or pick(WIN_LEGIT_USERS[:5])
    answers['compromised_account'] = compromised_user

    attack_start = random.randint(
        start_ts + int((end_ts - start_ts) * 0.3),
        start_ts + int((end_ts - start_ts) * 0.5)
    )
    current_ts = attack_start

    custom_procs = get_override(overrides, 'win_custom_procs', None)
    if custom_procs and isinstance(custom_procs, list) and len(custom_procs) > 0:
        procs = []
        for cmd_line in custom_procs:
            parts = cmd_line.split(' ', 1)
            exe = parts[0]
            args = parts[1] if len(parts) > 1 else ''
            procs.append((exe, f'C:\\Windows\\System32\\{exe}', args))
    else:
        procs = WIN_SUSPICIOUS_PROCS

    counts = {'easy': (5, 8), 'medium': (8, 14), 'hard': (len(procs), len(procs))}
    lo, hi = counts.get(difficulty, (8, 14))
    proc_count = random.randint(lo, min(hi, len(procs)))
    selected_procs = procs[:proc_count]

    parent_procs = [
        r'C:\Windows\System32\cmd.exe',
        r'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe',
        r'C:\Windows\System32\inetsrv\w3wp.exe',
    ]

    for proc in selected_procs:
        dt = datetime.fromtimestamp(current_ts)
        parent_proc = pick(parent_procs)
        proc_id = hex(random.randint(0x100, 0xFFFF))[2:].upper()
        msg = (f'A new process has been created. Creator Subject: Account Name: {compromised_user} '
               f'Account Domain: {domain} New Process Information: '
               f'New Process ID: 0x{proc_id} New Process Name: {proc[1]} '
               f'Creator Process Name: {parent_proc} '
               f'Process Command Line: {proc[1]} {proc[2]}')
        lines.append({
            'timestamp': dt,
            'line': format_win_event_line(dt, 4688, 'Information', hostname,
                                          'Microsoft-Windows-Security-Auditing', msg),
        })
        answers['suspicious_processes'].append(f'{proc[0]} {proc[2]}')
        current_ts += random.randint(3, 30)

    # 4720 — attacker creates a user
    new_user = 'svc_update'
    dt = datetime.fromtimestamp(current_ts)
    msg = (f'A user account was created. Subject: Account Name: {compromised_user} '
           f'Account Domain: {domain} New Account: Account Name: {new_user} '
           f'Account Domain: {domain}')
    lines.append({
        'timestamp': dt,
        'line': format_win_event_line(dt, 4720, 'Information', hostname,
                                      'Microsoft-Windows-Security-Auditing', msg),
    })
    answers['created_users'].append(new_user)
    current_ts += random.randint(2, 10)

    # 4732 — add to Administrators group
    dt = datetime.fromtimestamp(current_ts)
    msg = (f'A member was added to a security-enabled local group. '
           f'Subject: Account Name: {compromised_user} Account Domain: {domain} '
           f'Member: Account Name: {new_user} Group: Group Name: Administrators')
    lines.append({
        'timestamp': dt,
        'line': format_win_event_line(dt, 4732, 'Information', hostname,
                                      'Microsoft-Windows-Security-Auditing', msg),
    })
    current_ts += random.randint(10, 60)

    # 7045 — malicious service installed
    mal_services = [
        ('WindowsUpdateSvc', 'C:\\Windows\\Temp\\svchost.exe'),
        ('SystemHealthMonitor', 'cmd.exe /c C:\\Windows\\Temp\\payload.exe'),
        ('WinDefendExtension', 'powershell.exe -ep bypass -file C:\\Windows\\Temp\\persist.ps1'),
    ]
    mal_svc = pick(mal_services)
    dt = datetime.fromtimestamp(current_ts)
    msg = (f'A service was installed in the system. Service Name: {mal_svc[0]} '
           f'Service File Name: {mal_svc[1]} Service Type: user mode service '
           f'Service Start Type: auto start Service Account: LocalSystem')
    lines.append({
        'timestamp': dt,
        'line': format_win_event_line(dt, 7045, 'Information', hostname, 'System', msg),
    })
    answers['malicious_services'].append({'name': mal_svc[0], 'path': mal_svc[1]})

    return {'lines': lines, 'answers': answers}
