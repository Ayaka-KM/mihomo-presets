#!/usr/bin/env python3
"""Load the generated presets into a real mihomo core and check that it accepts them.

  validate.py --mihomo BIN --out DIR [--mmdb Country.mmdb] [--report validate.md]

1. `mihomo -t` on config-example.yaml with every fragment merged in.
2. Start the core with the rule-sets as local file providers and compare the rule count
   it reports for each rule-set with the number of entries written, so that no entry is
   silently skipped.
3. Ask its DNS for names covered by the Fake-IP filter (they must not get a fake IP) and
   for a name outside it (it must).
"""

import argparse
import ipaddress
import json
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

import yaml

FAKE_IP_RANGE = '198.18.0.1/16'
PLACEHOLDER_RE = re.compile(r'\$\{[^}]*\}')


def free_port(kind=socket.SOCK_STREAM):
    with socket.socket(socket.AF_INET, kind) as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def entries(path):
    return [line.strip() for line in path.read_text(encoding='utf-8').splitlines()
            if line.strip() and not line.strip().startswith('#')]


def strip_placeholders(node):
    if isinstance(node, str):
        return PLACEHOLDER_RE.sub('DIRECT', node)
    if isinstance(node, list):
        return [strip_placeholders(item) for item in node]
    if isinstance(node, dict):
        return {strip_placeholders(key): strip_placeholders(value) for key, value in node.items()}
    return node


def deep_merge(base, extra):
    for key, value in extra.items():
        if key == 'rules' and isinstance(value, list):
            base[key] = value + [rule for rule in base.get(key, []) if rule not in value]
        elif isinstance(value, dict) and isinstance(base.get(key), dict):
            deep_merge(base[key], value)
        else:
            base[key] = value
    return base


def domain_matches(pattern, name):
    """mihomo's domain set semantics: exact, *.x (one label), .x (subdomains), +.x (both)."""
    pattern, name = pattern.lower(), name.lower()
    if pattern.startswith('+.'):
        return domain_matches(pattern[2:], name) or domain_matches('.' + pattern[2:], name)
    if pattern.startswith('.'):
        return name.endswith(pattern) and len(name) > len(pattern)
    want, have = pattern.split('.'), name.split('.')
    return len(want) == len(have) and all(w in ('*', h) for w, h in zip(want, have))


def sample_name(pattern):
    if ' ' in pattern:
        return None
    if pattern.startswith('+.'):
        pattern = pattern[2:]
    elif pattern.startswith('.'):
        pattern = 'x' + pattern
    return '.'.join('oc-check' if label == '*' else label for label in pattern.split('.'))


def pick_filtered_samples(patterns):
    """A few concrete names covered by the filter: exact, +., leading *, inner *."""
    picks = {}
    for pattern in patterns:
        kind = ('suffix' if pattern.startswith('+.') else 'leading' if pattern.startswith('*.')
                else 'inner' if '*' in pattern else 'exact')
        name = sample_name(pattern)
        if name and kind not in picks and domain_matches(pattern, name):
            picks[kind] = (pattern, name)
    return list(picks.values())


def dns_query(port, name, timeout=10.0):
    """A records for name from the core's DNS, None when it does not answer in time."""
    query_id = secrets.randbits(16)
    question = b''.join(bytes([len(label)]) + label.encode() for label in name.split('.')) + b'\x00'
    packet = struct.pack('>HHHHHH', query_id, 0x0100, 1, 0, 0, 0) + question + struct.pack('>HH', 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(timeout)
        try:
            sock.sendto(packet, ('127.0.0.1', port))
            data, _ = sock.recvfrom(4096)
        except socket.timeout:
            return None
        except OSError:
            return None

    def skip_name(offset):
        while True:
            length = data[offset]
            if length == 0:
                return offset + 1
            if length & 0xC0 == 0xC0:
                return offset + 2
            offset += 1 + length

    _, _, qdcount, ancount, _, _ = struct.unpack('>HHHHHH', data[:12])
    offset = 12
    for _ in range(qdcount):
        offset = skip_name(offset) + 4
    addresses = []
    for _ in range(ancount):
        offset = skip_name(offset)
        rtype, _, _, length = struct.unpack('>HHIH', data[offset:offset + 10])
        offset += 10
        if rtype == 1 and length == 4:
            addresses.append(socket.inet_ntoa(data[offset:offset + 4]))
        offset += length
    return addresses


def api_get(port, secret, path):
    request = urllib.request.Request(f'http://127.0.0.1:{port}{path}', headers={'Authorization': f'Bearer {secret}'})
    with urllib.request.urlopen(request, timeout=5) as response:
        return json.loads(response.read().decode())


def build_config(out, home):
    """config-example.yaml with local file providers and every fragment merged in."""
    config = yaml.safe_load((out / 'config-example.yaml').read_text(encoding='utf-8'))
    expected = {}
    for name, provider in config.get('rule-providers', {}).items():
        source = out / ('rules/' + provider['url'].rsplit('/rules/', 1)[1])
        target = home / provider['path']
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(source, target)
        expected[name] = len(entries(source))
        config['rule-providers'][name] = {
            'type': 'file', 'behavior': provider['behavior'], 'format': provider['format'], 'path': provider['path'],
        }
    config['rules'] = [re.sub(r',PROXY$', ',DIRECT', rule) for rule in config.get('rules', [])]
    fragments = sorted((out / 'fragments').glob('*.yaml'))
    for fragment in fragments:
        deep_merge(config, strip_placeholders(yaml.safe_load(fragment.read_text(encoding='utf-8')) or {}))
    return config, expected, [f.name for f in fragments]


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--mihomo', required=True)
    parser.add_argument('--out', required=True, help='directory written by extract.py build')
    parser.add_argument('--mmdb', help='Country.mmdb to preload, keeps the geoip check offline')
    parser.add_argument('--report', help='write a markdown summary here')
    args = parser.parse_args()

    out = Path(args.out).resolve()
    home = Path(tempfile.mkdtemp(prefix='mihomo-presets-'))
    failures, lines = [], ['## mihomo 校验', '']
    version = (subprocess.run([args.mihomo, '-v'], capture_output=True, text=True).stdout.strip().splitlines() or ['?'])[0]
    lines += [f'内核：`{version}`', '']
    if args.mmdb and Path(args.mmdb).is_file():
        shutil.copyfile(args.mmdb, home / 'Country.mmdb')

    config, expected, fragment_names = build_config(out, home)
    api_port, dns_port, secret = free_port(), free_port(socket.SOCK_DGRAM), secrets.token_hex(16)
    config.update({
        'mixed-port': free_port(), 'allow-lan': False, 'bind-address': '127.0.0.1', 'mode': 'rule',
        'log-level': 'info', 'external-controller': f'127.0.0.1:{api_port}', 'secret': secret,
        'geo-auto-update': False, 'find-process-mode': 'off',
        'profile': {'store-selected': False, 'store-fake-ip': False},
    })
    dns = config.setdefault('dns', {})
    dns.update({'enable': True, 'listen': f'127.0.0.1:{dns_port}', 'enhanced-mode': 'fake-ip', 'fake-ip-range': FAKE_IP_RANGE})
    config_path = home / 'config.yaml'
    config_path.write_text(yaml.safe_dump(config, sort_keys=False, allow_unicode=True), encoding='utf-8')

    # 1. Syntax and semantic check, with the fragments exactly as published.
    test = subprocess.run([args.mihomo, '-t', '-d', str(home), '-f', str(config_path)],
                          capture_output=True, text=True, timeout=120)
    if test.returncode == 0 and 'test is successful' in test.stdout:
        lines.append(f"- `mihomo -t`：通过（config-example.yaml + {len(fragment_names)} 个片段）")
    else:
        failures.append('mihomo -t 未通过')
        lines += ['- `mihomo -t`：**失败**', '', '```', (test.stdout + test.stderr).strip()[-3000:], '```', '']

    # 2. Run it: NTP would try to set the clock, the rest stays as published.
    config['ntp'] = {'enable': False}
    config_path.write_text(yaml.safe_dump(config, sort_keys=False, allow_unicode=True), encoding='utf-8')
    log_path = home / 'mihomo.log'
    with open(log_path, 'w', encoding='utf-8') as log:
        core = subprocess.Popen([args.mihomo, '-d', str(home), '-f', str(config_path)], stdout=log, stderr=subprocess.STDOUT)
    try:
        providers, deadline = {}, time.time() + 40
        while time.time() < deadline and core.poll() is None:
            try:
                # null until the providers are loaded
                providers = api_get(api_port, secret, '/providers/rules').get('providers') or {}
                if all(providers.get(name, {}).get('ruleCount', 0) > 0 for name in expected):
                    break
            except (urllib.error.URLError, ConnectionError, OSError, ValueError):
                pass
            time.sleep(0.5)
        if core.poll() is not None:
            failures.append('内核启动后退出')
            lines.append('- 内核启动：**失败**（进程已退出，日志见下）')
        else:
            lines += ['', '| 规则集 | 写入条目 | 内核加载 | 结果 |', '|---|---|---|---|']
            for name, count in expected.items():
                loaded = providers.get(name, {}).get('ruleCount')
                ok = loaded == count
                if not ok:
                    failures.append(f'{name}：写入 {count} 条，内核加载 {loaded}')
                lines.append(f"| {name} | {count} | {loaded} | {'✅' if ok else '❌'} |")
            lines.append('')

            # 3. Fake-IP filter end to end through the core's DNS.
            filter_path = out / 'rules/fake-ip-filter.list'
            if 'oc-fake-ip-filter' in expected and filter_path.is_file():
                patterns = entries(filter_path)
                outside = f'oc-presets-{secrets.token_hex(4)}.mihomo-check.net'
                if any(domain_matches(pattern, outside) for pattern in patterns):
                    outside = None
                checks = [(None, outside, True)] if outside else []
                checks += [(pattern, name, False) for pattern, name in pick_filtered_samples(patterns)]
                fake = ipaddress.ip_network(FAKE_IP_RANGE, strict=False)
                for pattern, name, want_fake in checks:
                    answer = dns_query(dns_port, name)
                    got_fake = any(ipaddress.ip_address(ip) in fake for ip in answer or [])
                    ok = got_fake == want_fake
                    shown = '超时' if answer is None else (', '.join(answer) or '无 A 记录')
                    rule = f'命中 `{pattern}`，不应拿到假 IP' if pattern else '不在过滤列表里，应拿到假 IP'
                    lines.append(f"- DNS `{name}`（{rule}）：{shown} {'✅' if ok else '❌'}")
                    if not ok:
                        failures.append(f'Fake-IP 过滤检查失败：{name}')
                lines.append('')
    finally:
        if core.poll() is None:
            core.terminate()
            try:
                core.wait(timeout=10)
            except subprocess.TimeoutExpired:
                core.kill()

    log_lines = log_path.read_text(encoding='utf-8', errors='replace').splitlines()
    skipped = [line for line in log_lines if 'skip invalid' in line]
    problems = [line for line in log_lines if 'level=error' in line or 'level=fatal' in line or line in skipped]
    if skipped:
        failures.append(f'内核跳过了 {len(skipped)} 条无效条目')
    if problems or failures:
        lines += ['<details><summary>内核日志里的错误</summary>', '', '```', *problems[-50:], '```', '', '</details>', '']
    lines.append('**结果：通过**' if not failures else '**结果：失败**\n\n' + '\n'.join(f'- {item}' for item in failures))
    report = '\n'.join(lines) + '\n'
    if args.report:
        Path(args.report).write_text(report, encoding='utf-8')
    print(report)
    shutil.rmtree(home, ignore_errors=True)
    sys.exit(1 if failures else 0)


if __name__ == '__main__':
    main()
