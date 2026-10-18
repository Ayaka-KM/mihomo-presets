#!/usr/bin/env python3
"""Extract OpenClash's built-in presets into files a bare mihomo core can use.

  extract.py settings --config config.yaml   print KEY=VALUE lines for $GITHUB_OUTPUT
  extract.py paths                           print the upstream paths to sparse-checkout
  extract.py build ...                       generate the outputs, compare them with the
                                             published ones and write the change report

List presets become text rule-sets that mihomo pulls through rule-providers, the rest
becomes YAML fragments to merge by hand. Values that live in OpenClash's shell scripts
are matched by pattern: when upstream rewrites that code the build fails loudly instead
of publishing something half extracted.
"""

import argparse
import difflib
import hashlib
import ipaddress
import json
import os
import re
import shlex
import shutil
import subprocess
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import yaml

ROOT = 'luci-app-openclash/root'
SOURCES = {
    'fake-ip-filter': f'{ROOT}/etc/openclash/custom/openclash_custom_fake_filter.list',
    'localnetwork-ipv4': f'{ROOT}/etc/openclash/custom/openclash_custom_localnetwork_ipv4.list',
    'localnetwork-ipv6': f'{ROOT}/etc/openclash/custom/openclash_custom_localnetwork_ipv6.list',
    'fallback-filter': f'{ROOT}/etc/openclash/custom/openclash_custom_fallback_filter.yaml',
    'sniffer': f'{ROOT}/etc/openclash/custom/openclash_custom_sniffer.yaml',
    'uci': f'{ROOT}/etc/config/openclash',
    'yml-change': f'{ROOT}/usr/share/openclash/yml_change.sh',
    'yml-rules-change': f'{ROOT}/usr/share/openclash/yml_rules_change.sh',
    'license': 'LICENSE',
}
OVERWRITE_DIR = f'{ROOT}/etc/openclash/overwrite'
# Not a preset: validate.py loads it so that fallback-filter's geoip check works offline.
MMDB = f'{ROOT}/etc/openclash/Country.mmdb'

# Published files that change on every publish, left out of the change detection.
UNTRACKED = {'SOURCES.json', 'CHANGELOG.md'}
# Generated from the other outputs, the report only flags them instead of showing a diff.
DERIVED = {'README.md', 'config-example.yaml'}
CHANGELOG_KEEP = 100
GENERATED_NOTE = '由 mihomo-presets 工作流自动生成，请勿手改；按需取舍请改仓库默认分支上的 config.yaml'
CST = timezone(timedelta(hours=8))

RULE_SETS = {
    'fake-ip-filter': {
        'path': 'rules/fake-ip-filter.list',
        'behavior': 'domain',
        'title': 'OpenClash 预设：Fake-IP 过滤（这些域名需要真实 IP）',
        'usage': '在 dns.fake-ip-filter 里写 rule-set:oc-fake-ip-filter 引用',
    },
    'localnetwork': {
        'path': 'rules/localnetwork.list',
        'behavior': 'ipcidr',
        'title': 'OpenClash 预设：本地网络绕过（发往这些地址的流量不走代理）',
        'usage': '在 tun.route-exclude-address-set 里引用，或写成 RULE-SET,oc-localnetwork,DIRECT,no-resolve',
    },
    'bt-direct': {
        'path': 'rules/bt-direct.list',
        'behavior': 'classical',
        'title': 'OpenClash 预设：BT/PT tracker 直连（「仅代理命中规则流量」开关注入的规则）',
        'usage': '写成 RULE-SET,oc-bt-direct,DIRECT；有 GeoSite 数据时 OpenClash 优先改用 GEOSITE,category-public-tracker,DIRECT',
    },
    'process-direct': {
        'path': 'rules/process-direct.list',
        'behavior': 'classical',
        'title': 'OpenClash 预设：下载工具和其他代理程序按进程名直连',
        'usage': '写成 RULE-SET,oc-process-direct,DIRECT；只对路由器本机进程有效，find-process-mode 不能是 off',
    },
}

CLASSICAL_TYPES = {
    'DOMAIN', 'DOMAIN-SUFFIX', 'DOMAIN-KEYWORD', 'DOMAIN-REGEX', 'DOMAIN-WILDCARD', 'GEOSITE',
    'IP-CIDR', 'IP-CIDR6', 'IP-SUFFIX', 'IP-ASN', 'GEOIP', 'SRC-IP-CIDR', 'DST-PORT', 'SRC-PORT',
    'PROCESS-NAME', 'PROCESS-NAME-REGEX', 'PROCESS-PATH', 'PROCESS-PATH-REGEX', 'NETWORK',
}

IPV6_RE = re.compile(r'^([0-9a-fA-F]{0,4}:){1,7}[0-9a-fA-F]{0,4}$')
DNS_SCHEMES = {'tcp': 'tcp://', 'tls': 'tls://', 'udp': '', 'https': 'https://', 'quic': 'quic://'}
DNS_GROUPS = [
    ('default', 'default-nameserver'),
    ('nameserver', 'nameserver'),
    ('fallback', 'fallback'),
]

MODULE_META_RE = re.compile(r'^#!\s*([A-Za-z_]+)\s*[=:]\s*(.*)$')
SECTION_RE = re.compile(r'^\[([A-Za-z0-9_-]+)\]')
PLACEHOLDER_RE = re.compile(r'\$\{([A-Za-z_][A-Za-z0-9_]*)(?::-([^}]*))?\}')
SUFFIX_OPS = {'+': 'append', '-': 'delete', '!': 'force', '*': 'batch'}
GENERAL_HINTS = {
    'STACK_TYPE': '对应裸核的 tun.stack',
    'ENABLE_UDP_PROXY': 'OpenClash 非 TUN 模式的 UDP 转发开关，裸核用 TUN 时不需要',
    'CHINA_IP_ROUTE_PASS': '从「绕过大陆 IP」里排除的域名；裸核用 route-exclude-address-set 绕过大陆 IP 时要自己处理',
    'CHINA_IP6_ROUTE_PASS': '同上（IPv6）',
}


class ExtractError(Exception):
    pass


# --------------------------------------------------------------------------- helpers

def read(base, rel):
    path = Path(base) / rel
    try:
        return path.read_text(encoding='utf-8')
    except FileNotFoundError:
        raise ExtractError(f'上游缺少文件 {rel}（路径可能改了）') from None


def dump_yaml(data):
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=True, default_flow_style=False, width=1000)


def comment_block(lines):
    return '\n'.join(f'# {line}' if line else '#' for line in lines)


def blob_url(upstream, rel):
    return f"https://github.com/{upstream['repository']}/blob/{upstream['ref']}/{rel}"


def domain_error(domain):
    """Why mihomo's domain rule-set would skip this entry, None when it accepts it.

    Mirrors trie.ValidAndSplitDomain plus the slash check of the domain strategy."""
    if not domain:
        return '空条目'
    if '/' in domain:
        return '不能包含斜杠'
    if domain.endswith('.'):
        return '不能以点结尾'
    if domain != domain.strip():
        return '首尾不能有空白'
    parts = domain.lower().split('.')
    if len(parts) == 1:
        if not parts[0]:
            return '空条目'
    elif any(not part for part in parts[1:]):
        return '有空的标签'
    for index, part in enumerate(parts):
        if '+' in part:
            if part != '+':
                return '"+" 必须单独占一个标签'
            if index != 0:
                return '"+" 只能出现在第一个标签'
            if len(parts) == 1:
                return '"+" 后面必须还有标签'
        if '*' in part and part != '*':
            return '"*" 必须单独占一个标签'
    return None


def ipcidr_error(entry):
    try:
        ipaddress.ip_network(entry, strict=False)
    except ValueError as err:
        return str(err)
    return None


def classical_error(entry):
    rule_type = entry.split(',', 1)[0]
    if rule_type not in CLASSICAL_TYPES or ',' not in entry:
        return f'不认识的规则类型 {rule_type}'
    return None


def strip_policy(rule):
    parts = rule.split(',')
    if len(parts) >= 3 and parts[-1] == 'DIRECT':
        parts = parts[:-1]
    return ','.join(parts)


def uci_bool(value, default=False):
    if value is None:
        return default
    return str(value).lower() in ('1', 'true', 'yes', 'on', 'enabled')


def parse_uci(text):
    sections = []
    current = None
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith('#'):
            continue
        try:
            tokens = shlex.split(line)
        except ValueError:
            continue
        if not tokens:
            continue
        if tokens[0] == 'config' and len(tokens) >= 2:
            current = {'.type': tokens[1], '.name': tokens[2] if len(tokens) > 2 else None}
            sections.append(current)
        elif tokens[0] == 'option' and current is not None and len(tokens) >= 3:
            current[tokens[1]] = tokens[2]
        elif tokens[0] == 'list' and current is not None and len(tokens) >= 3:
            current.setdefault(tokens[1], []).append(tokens[2])
    return sections


def search(pattern, text, what, flags=0):
    match = re.search(pattern, text, flags)
    if not match:
        raise ExtractError(f'{what}：在上游代码里找不到（上游可能改了写法，需要更新 extract.py）')
    return match


def quoted(text):
    return re.findall(r"'([^']*)'", text)


def ruby_scalar(token):
    token = token.strip()
    if token.startswith("'") and token.endswith("'"):
        return token[1:-1]
    if token in ('true', 'false'):
        return token == 'true'
    if token.isdigit():
        return int(token)
    raise ExtractError(f'无法识别的值 {token}')


# --------------------------------------------------------------------------- settings

def load_config(path):
    with open(path, encoding='utf-8') as handle:
        config = yaml.safe_load(handle) or {}
    config.setdefault('upstream', {})
    config['upstream'].setdefault('repository', 'vernesong/OpenClash')
    config['upstream'].setdefault('ref', 'dev')
    config.setdefault('validator', {})
    config['validator'].setdefault('repository', 'MetaCubeX/mihomo')
    config['validator'].setdefault('release', 'latest')
    config.setdefault('rules', {})
    config.setdefault('fragments', {})
    return config


def rule_options(config, name):
    options = config['rules'].get(name) or {}
    return {
        'enabled': options.get('enabled', name != 'process-direct'),
        'exclude': [str(item) for item in options.get('exclude') or []],
        'include': [str(item) for item in options.get('include') or []],
    }


def fragment_enabled(config, name):
    value = config['fragments'].get(name, True)
    if isinstance(value, dict):
        return value.get('enabled', True)
    return bool(value)


# --------------------------------------------------------------------------- rule-sets

def finish_rule_set(name, body, options, validate, notes):
    """Apply include/exclude, validate the entries and render the rule-set file."""
    exclude = set(options['exclude'])
    kept, invalid = [], []
    out_lines = []
    seen = set()
    for kind, value in body:
        if kind == 'comment':
            out_lines.append(f'# {value}' if value else '#')
            continue
        if value in exclude:
            notes.append(f'{name}：按 config.yaml 去掉 `{value}`')
            continue
        error = validate(value)
        if error:
            invalid.append((value, error))
            continue
        if value in seen:
            continue
        seen.add(value)
        kept.append(value)
        out_lines.append(value)
    extra = []
    for value in options['include']:
        error = validate(value)
        if error:
            raise ExtractError(f'config.yaml 里 {name}.include 的 `{value}` 无效：{error}')
        if value not in seen:
            seen.add(value)
            extra.append(value)
    if extra:
        out_lines += ['', '# 本地追加（config.yaml）'] + extra
        kept += extra
    for value, error in invalid:
        notes.append(f'{name}：跳过上游无效条目 `{value}`（{error}）')
    if len(kept) < 1:
        raise ExtractError(f'{name}：一条有效条目都没有提取到')
    return out_lines, kept


def build_fake_ip_filter(upstream_dir, options, notes):
    body, inline_only = [], []
    for raw in read(upstream_dir, SOURCES['fake-ip-filter']).splitlines():
        line = raw.strip()
        if not line:
            continue
        if line.startswith('#'):
            body.append(('comment', line[1:].strip()))
        elif line.lower().startswith(('geosite:', 'rule-set:', 'geoip:')):
            # Only valid inline in dns.fake-ip-filter, a domain rule-set would take them literally.
            inline_only.append(line)
        else:
            body.append(('entry', line))
    count = sum(1 for kind, _ in body if kind == 'entry')
    if count < 20:
        raise ExtractError(f'fake-ip-filter：上游只有 {count} 条，和以往相差太多')
    lines, kept = finish_rule_set('fake-ip-filter', body, options, domain_error, notes)
    return lines, kept, inline_only


def build_localnetwork(upstream_dir, options, notes):
    body = []
    for key, label in (('localnetwork-ipv4', 'IPv4'), ('localnetwork-ipv6', 'IPv6')):
        body.append(('comment', label))
        for raw in read(upstream_dir, SOURCES[key]).splitlines():
            entry, _, comment = raw.partition('#')
            entry, comment = entry.strip(), comment.strip()
            if not entry:
                continue
            if comment:
                # The text format has no inline comments, keep the note on its own line.
                body.append(('comment', comment))
            body.append(('entry', entry))
    upstream_entries = [value for kind, value in body if kind == 'entry']
    if not any(':' in item for item in upstream_entries) or not any('.' in item for item in upstream_entries):
        raise ExtractError('localnetwork：上游的 IPv4 或 IPv6 网段缺失')
    return finish_rule_set('localnetwork', body, options, ipcidr_error, notes)


def build_bt_direct(upstream_dir, options, notes):
    src = read(upstream_dir, SOURCES['yml-rules-change'])
    blocks = re.findall(r"bt_rules\s*=\s*\[(.*?)\]\s*;", src, re.S)
    if not blocks:
        raise ExtractError('BT/PT 直连规则（bt_rules）：在上游代码里找不到（上游可能改了写法，需要更新 extract.py）')
    rules = max((quoted(block) for block in blocks), key=len)
    if len(rules) < 10:
        raise ExtractError(f'BT/PT 直连规则：只提取到 {len(rules)} 条')
    body = [('entry', strip_policy(rule)) for rule in rules]
    return finish_rule_set('bt-direct', body, options, classical_error, notes)


def build_process_direct(upstream_dir, options, notes):
    src = read(upstream_dir, SOURCES['yml-rules-change'])
    block = search(r"process_rules\s*=\s*\[(.*?)\]\s*;", src, '进程名直连规则（process_rules）', re.S)
    rules = [strip_policy(rule) for rule in quoted(block.group(1)) if rule.startswith('PROCESS-NAME,')]
    if len(rules) < 5:
        raise ExtractError(f'进程名直连规则：只提取到 {len(rules)} 条')
    body = [('entry', rule) for rule in rules]
    return finish_rule_set('process-direct', body, options, classical_error, notes)


def render_rule_set(upstream, name, lines, sources):
    spec = RULE_SETS[name]
    head = [spec['title']] + [f'来源：{blob_url(upstream, rel)}' for rel in sources]
    head += [f"behavior: {spec['behavior']}，format: text；{spec['usage']}", GENERATED_NOTE]
    return comment_block(head) + '\n\n' + '\n'.join(lines).rstrip() + '\n'


# --------------------------------------------------------------------------- fragments

def indent_yaml(text, indent='  '):
    return '\n'.join(indent + line if line.strip() else '' for line in text.splitlines())


def build_fallback_filter(upstream, upstream_dir):
    rel = SOURCES['fallback-filter']
    text = read(upstream_dir, rel)
    data = yaml.safe_load(text) or {}
    expected = data.get('fallback-filter')
    if not isinstance(expected, dict):
        raise ExtractError('fallback-filter：上游文件里没有 fallback-filter 段')
    body = 'dns:\n' + indent_yaml(text.strip('\n'))
    if (yaml.safe_load(body) or {}).get('dns', {}).get('fallback-filter') != expected:
        body = dump_yaml({'dns': {'fallback-filter': expected}})
    head = [
        'OpenClash 预设：dns.fallback-filter（覆写设置 → DNS →「自定义 Fallback-Filter」）',
        f'来源：{blob_url(upstream, rel)}',
        '只在配置了 dns.fallback 时生效；geoip 判断依赖 Country.mmdb（OpenClash 默认用只含中国 IP 的精简版，见 geox-url.yaml）',
        GENERATED_NOTE,
    ]
    return comment_block(head) + '\n\n' + body.rstrip() + '\n', [rel]


def build_sniffer(upstream, upstream_dir):
    rel = SOURCES['sniffer']
    text = read(upstream_dir, rel)
    data = yaml.safe_load(text) or {}
    sniffer = data.get('sniffer')
    if not isinstance(sniffer, dict):
        raise ExtractError('sniffer：上游文件里没有 sniffer 段')
    body = text.strip('\n')
    expected = dict(sniffer)
    if 'enable' not in sniffer:
        # OpenClash merges this file into its own enabled sniffer, standalone it needs the switch.
        expected = {'enable': True, **sniffer}
        child = re.search(r'^sniffer:\s*\n(?:\s*#.*\n|\s*\n)*([ \t]+)\S', body + '\n', re.M)
        indent = child.group(1) if child else '  '
        body = re.sub(r'^sniffer:\s*$', f'sniffer:\n{indent}enable: true', body, count=1, flags=re.M)
    if (yaml.safe_load(body) or {}).get('sniffer') != expected:
        body = dump_yaml({'sniffer': expected})
    head = [
        'OpenClash 预设：域名嗅探（覆写设置 → Meta →「自定义嗅探」使用的文件）',
        f'来源：{blob_url(upstream, rel)}',
        '上游文件原本没有 enable（OpenClash 会合并进自己开启的嗅探配置），这里已补上 enable: true',
        GENERATED_NOTE,
    ]
    return comment_block(head) + '\n\n' + body.rstrip() + '\n', [rel]


def build_hosts(upstream, upstream_dir):
    rel = SOURCES['yml-change']
    src = read(upstream_dir, rel)
    block = search(r'builtin_hosts\s*=\s*\{(.*?)\}', src, '内置 hosts（builtin_hosts）', re.S)
    pairs = re.findall(r"'([^']+)'\s*=>\s*'([^']+)'", block.group(1))
    if not pairs:
        raise ExtractError('内置 hosts：没有提取到条目')
    head = [
        'OpenClash 预设：路由器常见主机名解析到路由器自身（yml_change.sh 每次启动都会加上）',
        f'来源：{blob_url(upstream, rel)}',
        'lan 是 mihomo 的特殊值，代表本机所有网卡的地址',
        'OpenClash 还会动态加上 <系统主机名>.lan 和 <系统主机名>.<dnsmasq 域名>，请按你的路由器自行补充',
        GENERATED_NOTE,
    ]
    data = {'dns': {'use-hosts': True}, 'hosts': dict(pairs)}
    return comment_block(head) + '\n\n' + dump_yaml(data), [rel]


def build_ntp(upstream, upstream_dir):
    rel = SOURCES['yml-change']
    src = read(upstream_dir, rel)
    enable = search(r"\(Value\['ntp'\]\s*\|\|=\s*\{\}\)\['enable'\]\s*=\s*(true|false)", src, 'NTP 开关')
    ntp = {'enable': enable.group(1) == 'true'}
    for key, value in re.findall(r"Value\['ntp'\]\['([a-z-]+)'\]\s*=\s*('[^']*'|\d+|true|false)\s+if", src):
        ntp[key] = ruby_scalar(value)
    if 'server' not in ntp:
        raise ExtractError('NTP：没有提取到默认服务器')
    head = [
        'OpenClash 预设：内核 NTP 对时（配置里没写的项由 OpenClash 补上）',
        f'来源：{blob_url(upstream, rel)}',
        '路由器多半没有硬件时钟，时间不准时 TLS、VMess 等协议会连不上；interval 单位是分钟，write-to-system 需要 root 权限',
        GENERATED_NOTE,
    ]
    return comment_block(head) + '\n\n' + dump_yaml({'ntp': ntp}), [rel]


def build_keep_alive(upstream, upstream_dir):
    rel = SOURCES['yml-change']
    src = read(upstream_dir, rel)
    interval = search(r"Value\['keep-alive-interval'\]\s*=\s*(\d+)", src, 'keep-alive-interval')
    idle = search(r"Value\['keep-alive-idle'\]\s*=\s*(\d+)", src, 'keep-alive-idle')
    head = [
        'OpenClash 预设：TCP keep-alive（配置里两项都没写时由 OpenClash 补上，单位秒）',
        f'来源：{blob_url(upstream, rel)}',
        GENERATED_NOTE,
    ]
    data = {'keep-alive-interval': int(interval.group(1)), 'keep-alive-idle': int(idle.group(1))}
    return comment_block(head) + '\n\n' + dump_yaml(data), [rel]


def build_geox_url(upstream, upstream_dir):
    rel = SOURCES['uci']
    sections = parse_uci(read(upstream_dir, rel))
    main = next((s for s in sections if s['.type'] == 'openclash'), None)
    if main is None:
        raise ExtractError('geox-url：UCI 默认配置里没有 openclash 段')
    mapping = [
        ('mmdb', 'geo_custom_url'),
        ('geoip', 'geoip_custom_url'),
        ('geosite', 'geosite_custom_url'),
        ('asn', 'geoasn_custom_url'),
    ]
    urls = {key: main[option] for key, option in mapping if main.get(option, '').startswith('http')}
    if not urls:
        raise ExtractError('geox-url：没有提取到数据源地址')
    head = [
        'OpenClash 预设：GEO 数据源（插件设置 → GEO 数据库订阅的默认地址）',
        f'来源：{blob_url(upstream, rel)}',
        '注意 mmdb 是只含中国 IP 的精简版：体积小，但只能判断是不是 CN',
        GENERATED_NOTE,
    ]
    return comment_block(head) + '\n\n' + dump_yaml({'geox-url': urls}), [rel]


def dns_address(section):
    """Same address string OpenClash builds in yml_dns_get (proxy group params left out)."""
    ip = section.get('ip', '')
    if IPV6_RE.search(ip):
        ip = f'[{ip}]'
    port = section.get('port', '')
    if port:
        host, slash, path = ip.partition('/')
        address = f'{host}:{port}/{path}' if slash else f'{ip}:{port}'
    else:
        address = ip
    params = []
    interface = section.get('interface', '')
    if interface and interface != 'Disable':
        params.append(interface)
    if uci_bool(section.get('http3')):
        params.append('h3=true')
    if uci_bool(section.get('skip_cert_verify')):
        params.append('skip-cert-verify=true')
    ecs = section.get('ecs_subnet', '')
    if ecs:
        params.append(f'ecs={ecs}')
        if uci_bool(section.get('ecs_override')):
            params.append('ecs-override=true')
    if uci_bool(section.get('disable_ipv4')):
        params.append('disable-ipv4=true')
    if uci_bool(section.get('disable_ipv6')):
        params.append('disable-ipv6=true')
    qtypes = section.get('disable_qtype') or []
    if isinstance(qtypes, str):
        qtypes = [qtypes]
    params += [f'disable-qtype-{qtype}=true' for qtype in qtypes]
    if uci_bool(section.get('disable_reuse')):
        params.append('disable-reuse=true')
    suffix = '#' + '&'.join(params) if params else ''
    return DNS_SCHEMES.get(section.get('type', ''), '') + address + suffix


def build_dns_servers(upstream, upstream_dir):
    uci_rel, code_rel = SOURCES['uci'], SOURCES['yml-change']
    servers = [s for s in parse_uci(read(upstream_dir, uci_rel)) if s['.type'] == 'dns_servers' and s.get('ip')]
    if len(servers) < 5:
        raise ExtractError(f'预置 DNS：只找到 {len(servers)} 个 dns_servers 段')
    group_names = dict(DNS_GROUPS)
    enabled = {key: [] for _, key in DNS_GROUPS}
    extra = {'proxy-server-nameserver': [], 'direct-nameserver': []}
    spare = []
    for section in servers:
        address = dns_address(section)
        key = group_names.get(section.get('group', ''))
        if not uci_bool(section.get('enabled'), default=True):
            spare.append(f"{key or section.get('group', '?')}: {address}")
            continue
        if key:
            enabled[key].append(address)
        if uci_bool(section.get('node_resolve')):
            extra['proxy-server-nameserver'].append(address)
        if uci_bool(section.get('direct_nameserver')):
            extra['direct-nameserver'].append(address)
    dns = {key: values for key, values in {**enabled, **extra}.items() if values}
    if not dns.get('nameserver'):
        raise ExtractError('预置 DNS：默认启用的 nameserver 为空')

    src = read(upstream_dir, code_rel)
    fill_ns = quoted(search(r"Value\['dns'\]\['nameserver'\]\s*=\s*\[([^\]]*)\]", src, 'nameserver 兜底值').group(1))
    fill_fb = quoted(search(r"Value\['dns'\]\['fallback'\]\s*\|\|=\s*\[([^\]]*)\]", src, 'fallback 兜底值').group(1))
    fill_def = quoted(search(r"Value\['dns'\]\['default-nameserver'\]\s*=\s*\[([^\]]*)\]", src, 'default-nameserver 兜底值').group(1))
    fill_psn = quoted(search(r"default_proxy_servers\s*=\s*\[([^\]]*)\]", src, 'proxy-server-nameserver 兜底值').group(1))

    head = [
        'OpenClash 预设：上游 DNS（覆写设置 → DNS →「自定义上游 DNS 服务器」默认勾选的那组）',
        f'来源：{blob_url(upstream, uci_rel)}（dns_servers 段）',
        f'来源：{blob_url(upstream, code_rel)}（兜底逻辑）',
        'OpenClash 只在开启「自定义上游 DNS 服务器」时才用这组替换配置里的 DNS；其余内置备选和兜底逻辑列在文末',
        GENERATED_NOTE,
    ]
    tail = ['内置备选（默认未启用）：'] + [f'  {item}' for item in spare]
    tail += [
        '',
        'OpenClash 的兜底逻辑（yml_change.sh）：',
        f"  nameserver 为空时补上：{', '.join(fill_ns)}",
        f"    同时 fallback 为空时补上：{', '.join(fill_fb)}",
        f"  default-nameserver 写了但为空时补上：{', '.join(fill_def)}",
        '  开启 respect-rules，或 nameserver 全部走代理时，自动设置 proxy-server-nameserver',
        f"    （避免节点域名解析回环）为：{', '.join(fill_psn)}",
        '  Dnsmasq 转发模式下删掉 system 上游（会造成 DNS 回环）',
    ]
    text = comment_block(head) + '\n\n' + dump_yaml({'dns': dns}) + '\n' + comment_block(tail) + '\n'
    return text, [uci_rel, code_rel]


def parse_module(text):
    """Split an overwrite module like init.d's overwrite_file does."""
    meta, intro, general, commands, yaml_lines = {}, [], [], [], []
    section = None
    for raw in text.splitlines():
        stripped = raw.strip()
        header = SECTION_RE.match(stripped)
        if header:
            name = header.group(1).lower()
            section = name if name in ('general', 'overwrite', 'yaml') else 'unknown'
            continue
        if section == 'yaml':
            yaml_lines.append(raw)
            continue
        if not stripped:
            continue
        meta_line = MODULE_META_RE.match(stripped)
        if meta_line:
            meta[meta_line.group(1).upper()] = meta_line.group(2).strip()
            continue
        if stripped.startswith(('#', ';')):
            if section is None:
                intro.append(stripped.lstrip('#;').strip())
            continue
        if section == 'general':
            key, _, value = stripped.partition('=')
            general.append((key.strip().upper(), value.strip()))
        elif section == 'overwrite':
            commands.append(stripped)
    return meta, intro, general, commands, '\n'.join(yaml_lines)


def parse_key(key):
    """Mirror YAML.parse_key in OpenClash's YAML.rb: (plain key, operation)."""
    if key.startswith('+<') and '>' in key:
        return key[2:key.index('>')], 'prepend'
    if key.startswith('<') and '>' in key:
        close = key.index('>')
        return key[1:close], SUFFIX_OPS.get(key[close + 1:], 'merge')
    if key.startswith('+'):
        return key[1:], 'prepend'
    if key and key[-1] in SUFFIX_OPS:
        return key[:-1], SUFFIX_OPS[key[-1]]
    return key, 'merge'


def translate_overwrite(data):
    """Expand OpenClash's overwrite operators into a plain fragment.

    Like YAML.rb, operators are only parsed on keys merged by default; the value of an
    append, prepend or force key is literal data (nameserver-policy domains start with +)."""
    notes, skipped = [], []

    def walk(node, path):
        out = {}
        for raw_key, value in node.items():
            key, op = parse_key(str(raw_key))
            where = '.'.join(path + [key])
            if op in ('delete', 'batch'):
                skipped.append((where, str(raw_key), op))
                continue
            if op == 'merge' and isinstance(value, dict):
                value = walk(value, path + [key])
            elif op != 'merge':
                notes.append((where, str(raw_key), op, isinstance(value, list)))
            if key in out and isinstance(out[key], list) and isinstance(value, list):
                out[key] = value + out[key] if op == 'prepend' else out[key] + value
            elif key in out and isinstance(out[key], dict) and isinstance(value, dict):
                out[key] = {**out[key], **value}
            else:
                out[key] = value
        return out

    if not isinstance(data, dict):
        raise ExtractError('覆写模块的 [YAML] 段不是映射')
    return walk(data, []), notes, skipped


def substitute(node, defaults, found):
    if isinstance(node, str):
        def replace(match):
            name, inline_default = match.group(1), match.group(2)
            value = inline_default if inline_default is not None else defaults.get(name)
            found.setdefault(name, value)
            return value if value is not None else match.group(0)
        return PLACEHOLDER_RE.sub(replace, node)
    if isinstance(node, list):
        return [substitute(item, defaults, found) for item in node]
    if isinstance(node, dict):
        return {substitute(key, defaults, found): substitute(value, defaults, found) for key, value in node.items()}
    return node


def describe_op(where, raw_key, op, is_list):
    if op == 'prepend':
        action = '放到你已有列表的最前面' if is_list else '合并进你已有的映射'
    elif op == 'append':
        action = '追加到你已有列表的末尾' if is_list else '合并进你已有的映射'
    else:
        action = '整体替换你已有的值'
    return f'{where}：{action}（原写法 {raw_key}）'


def build_module(upstream, upstream_dir, name):
    rel = f'{OVERWRITE_DIR}/{name}'
    meta, intro, general, commands, yaml_text = parse_module(read(upstream_dir, rel))
    try:
        data = yaml.safe_load(yaml_text) if yaml_text.strip() else None
    except yaml.YAMLError as err:
        raise ExtractError(f'覆写模块 {name}：[YAML] 段解析失败：{err}') from None
    if not data:
        return None, [rel]
    fragment, notes, skipped = translate_overwrite(data)
    defaults = {}
    for item in filter(None, (part.strip() for part in meta.get('ENV', '').split(';'))):
        key, sep, value = item.partition('=')
        defaults[key.strip()] = value.strip() if sep else None
    placeholders = {}
    fragment = substitute(fragment, defaults, placeholders)

    head = [f'OpenClash 官方覆写模块：{meta.get("NAME", name)}', f'来源：{blob_url(upstream, rel)}']
    if meta.get('DESC'):
        head.append(f'说明：{meta["DESC"]}')
    if intro and len(intro) <= 20:
        head += ['原注释：'] + [f'  {line}' for line in intro]
    head.append('合并方式（原模块用 OpenClash 的覆写操作符，这里已展开成普通配置）：')
    head += [f'  {describe_op(*note)}' for note in notes] or ['  直接合并进你的配置']
    for where, raw_key, op in skipped:
        head.append(f'  {where}：原写法 {raw_key} 是{"删除" if op == "delete" else "批量修改"}操作，没法变成静态片段，已跳过')
    for var, value in placeholders.items():
        if value is None:
            head.append(f'占位符 ${{{var}}} 保留原样，合并前要换成你自己的值')
        else:
            head.append(f'占位符 {var} 已替换为默认值 {value}，按需改成你自己的策略组')
    if general:
        head.append('插件设置（[General]，是 OpenClash 自身的开关，裸核里没有，仅供参考）：')
        for key, value in general:
            hint = GENERAL_HINTS.get(key)
            head.append(f'  {key} = {value}' + (f'  ← {hint}' if hint else ''))
    if commands:
        head.append('原模块还有 [Overwrite] 脚本命令，未转换：')
        head += [f'  {command}' for command in commands]
    head.append(GENERATED_NOTE)
    return comment_block(head) + '\n\n' + dump_yaml(fragment), [rel]


# --------------------------------------------------------------------------- example and readme

def raw_url(repo, branch, rel):
    return f'https://raw.githubusercontent.com/{repo}/{branch}/{rel}'


def build_example(repo, branch, rule_sets, inline_filters):
    providers, rules = {}, []
    for name in rule_sets:
        spec = RULE_SETS[name]
        providers[f'oc-{name}'] = {
            'type': 'http',
            'behavior': spec['behavior'],
            'format': 'text',
            'url': raw_url(repo, branch, spec['path']),
            'path': f'./ruleset/oc-{name}.list',
            'interval': 86400,
        }
    config = {'rule-providers': providers}
    if 'fake-ip-filter' in rule_sets:
        config['dns'] = {'enhanced-mode': 'fake-ip', 'fake-ip-filter': ['rule-set:oc-fake-ip-filter'] + inline_filters}
    if 'localnetwork' in rule_sets:
        config['tun'] = {'route-exclude-address-set': ['oc-localnetwork']}
        rules.append('RULE-SET,oc-localnetwork,DIRECT,no-resolve')
    for name in ('bt-direct', 'process-direct'):
        if name in rule_sets:
            rules.append(f'RULE-SET,oc-{name},DIRECT')
    rules.append('MATCH,PROXY')
    config['rules'] = rules
    head = [
        '把 OpenClash 预设接入裸 mihomo 的示例：只列出相关部分，合并进你自己的配置',
        '规则集由 mihomo 每天自动更新；fragments/ 下的片段需要手动合并，变化见 CHANGELOG.md',
        '国内直连 raw.githubusercontent.com 可能不通：可以给每个 rule-provider 加 proxy: <你的策略组>，',
        f'或把 url 换成 jsDelivr 镜像 https://testingcf.jsdelivr.net/gh/{repo}@{branch}/rules/<文件名>',
        'tun.route-exclude-address-set 需要 tun 开启 auto-route 和 auto-redirect（nftables）；没开 TUN 时用规则里的那条即可',
        'MATCH,PROXY 里的 PROXY 换成你自己的策略组',
    ]
    return comment_block(head) + '\n\n' + dump_yaml(config)


def build_readme(repo, branch, default_branch, upstream, rule_sets, fragments):
    lines = [
        '# OpenClash 预设（供裸 mihomo 使用）',
        '',
        f'本分支由 [{repo}](https://github.com/{repo}/tree/{default_branch}) 的工作流'
        f'每天从 [{upstream["repository"]}@{upstream["ref"]}](https://github.com/{upstream["repository"]}/tree/{upstream["ref"]}) '
        '自动提取生成，请勿手改。接入方法见 [`config-example.yaml`](config-example.yaml)，每次变化见 [`CHANGELOG.md`](CHANGELOG.md)。',
        '',
        '## 规则集（mihomo 通过 rule-providers 自动更新）',
        '',
        '| 文件 | behavior | 条目数 | 用法 |',
        '|---|---|---|---|',
    ]
    for name, count in rule_sets.items():
        spec = RULE_SETS[name]
        lines.append(f"| [`{spec['path']}`]({raw_url(repo, branch, spec['path'])}) | {spec['behavior']} | {count} | {spec['usage']} |")
    lines += ['', '## 配置片段（需要手动合并）', '', '| 文件 | 内容 |', '|---|---|']
    for path, title in fragments.items():
        lines.append(f'| [`{path}`]({path}) | {title} |')
    lines += ['', '## 许可', '',
              f'规则集和配置片段提取自 [{upstream["repository"]}](https://github.com/{upstream["repository"]})，'
              '沿用其许可证，原文见 [`LICENSE`](LICENSE)。']
    return '\n'.join(lines) + '\n'


# --------------------------------------------------------------------------- compare and report

def list_entries(text):
    return [line.strip() for line in text.splitlines() if line.strip() and not line.strip().startswith('#')]


def read_tree(directory):
    files = {}
    if not directory or not Path(directory).is_dir():
        return files
    base = Path(directory)
    for path in sorted(base.rglob('*')):
        rel = path.relative_to(base).as_posix()
        if rel == '.git' or rel.startswith('.git/') or not path.is_file():
            continue
        files[rel] = path.read_text(encoding='utf-8')
    return files


def compare(previous, outputs):
    old = {k: v for k, v in previous.items() if k not in UNTRACKED}
    new = {k: v for k, v in outputs.items() if k not in UNTRACKED}
    changes = []
    for rel in sorted(set(old) | set(new)):
        if old.get(rel) == new.get(rel):
            continue
        if rel not in old:
            changes.append({'path': rel, 'kind': 'added'})
        elif rel not in new:
            changes.append({'path': rel, 'kind': 'removed'})
        elif rel.endswith('.list'):
            before, after = list_entries(old[rel]), list_entries(new[rel])
            changes.append({
                'path': rel, 'kind': 'entries',
                'added': [e for e in after if e not in set(before)],
                'removed': [e for e in before if e not in set(after)],
            })
        else:
            diff = difflib.unified_diff(old[rel].splitlines(), new[rel].splitlines(), 'published', 'new', lineterm='', n=2)
            changes.append({'path': rel, 'kind': 'modified', 'diff': '\n'.join(diff)})
    return changes


def git(upstream_dir, *args):
    try:
        return subprocess.run(['git', '-C', str(upstream_dir), *args], check=True, capture_output=True, text=True).stdout.strip()
    except (subprocess.CalledProcessError, FileNotFoundError):
        return ''


def upstream_commits(upstream_dir, old_sha, new_sha, paths):
    if not new_sha:
        return [], False
    in_range = bool(old_sha) and old_sha != new_sha and bool(git(upstream_dir, 'cat-file', '-t', old_sha))
    revision = [f'{old_sha}..{new_sha}'] if in_range else ['-n', '10', new_sha]
    log = git(upstream_dir, 'log', '--format=%H%x09%ad%x09%s', '--date=short', *revision, '--', *paths)
    commits = [line.split('\t', 2) for line in log.splitlines() if line.count('\t') >= 2]
    return commits, in_range


def code(value):
    return '`' + value.replace('`', "'") + '`'


def build_report(upstream, sha, old_sha, commits, in_range, changes, notes, first):
    repo = upstream['repository']
    now = datetime.now(CST).strftime('%Y-%m-%d %H:%M')
    short = sha[:7] if sha else 'unknown'
    lines = [f'## {now}（北京时间）', '']
    span = f'[`{short}`](https://github.com/{repo}/commit/{sha})' if sha else '`unknown`'
    if old_sha and old_sha != sha:
        span = f'[`{old_sha[:7]}`](https://github.com/{repo}/commit/{old_sha}) → ' + span
    lines += [f'上游 [{repo}@{upstream["ref"]}](https://github.com/{repo}/tree/{upstream["ref"]})：{span}', '']
    if commits:
        lines.append('### 上游相关提交' if in_range else '### 上游最近的相关提交')
        lines.append('')
        lines += [f'- [`{c[0][:7]}`](https://github.com/{repo}/commit/{c[0]}) {c[1]} {c[2]}' for c in commits]
        lines.append('')
    if not changes:
        lines += ['与已发布版本一致，无需更新。', '']
    else:
        lines += ['### 首次发布' if first else '### 产出变化', '']
        for change in changes:
            path = change['path']
            if change['kind'] == 'added':
                lines.append(f'- `{path}`：新增文件')
            elif change['kind'] == 'removed':
                lines.append(f'- `{path}`：已删除')
            elif change['kind'] == 'entries':
                lines.append(f"- `{path}`：+{len(change['added'])} / -{len(change['removed'])}")
                if change['added']:
                    lines.append('  - 新增：' + '、'.join(code(e) for e in change['added']))
                if change['removed']:
                    lines.append('  - 删除：' + '、'.join(code(e) for e in change['removed']))
                if not change['added'] and not change['removed']:
                    lines.append('  - 只有注释或顺序变化')
            elif path in DERIVED:
                lines.append(f'- `{path}`：随上面的变化重新生成')
            else:
                lines += [f'- `{path}`：有改动', '', '<details><summary>diff</summary>', '', '```diff',
                          change['diff'], '```', '', '</details>', '']
        lines.append('')
    if notes:
        lines += ['### 备注', ''] + [f'- {note}' for note in notes] + ['']
    return '\n'.join(lines).rstrip() + '\n'


def commit_message(upstream, sha, changes):
    title = f"同步 OpenClash 预设：{upstream['repository']}@{upstream['ref']} {sha[:7] if sha else ''}".rstrip()
    body = []
    for change in changes:
        if change['kind'] == 'entries':
            body.append(f"- {change['path']}: +{len(change['added'])}/-{len(change['removed'])}")
        else:
            body.append(f"- {change['path']}: {change['kind']}")
    return title + ('\n\n' + '\n'.join(body) if body else '') + '\n'


def merge_changelog(entry, previous):
    old_entries = []
    if previous:
        parts = re.split(r'(?m)^(?=## )', previous)
        old_entries = [part for part in parts if part.startswith('## ')]
    entries = [entry] + old_entries[:CHANGELOG_KEEP - 1]
    return '# 变化记录\n\n' + '\n'.join(part.rstrip() + '\n' for part in entries)


# --------------------------------------------------------------------------- commands

def cmd_settings(args):
    config = load_config(args.config)
    for section, keys in (('upstream', ('repository', 'ref')), ('validator', ('repository', 'release'))):
        for key in keys:
            print(f'{section}_{key}={config[section][key]}')


def cmd_paths(_args):
    for rel in SOURCES.values():
        print(f'/{rel}')
    print(f'/{OVERWRITE_DIR}/')
    print(f'/{MMDB}')


def cmd_build(args):
    config = load_config(args.config)
    upstream = config['upstream']
    upstream_dir = Path(args.upstream)
    notes, outputs, used_sources = [], {}, set()
    rule_counts, fragment_titles, inline_filters = {}, {}, []

    builders = {
        'fake-ip-filter': lambda opts: build_fake_ip_filter(upstream_dir, opts, notes),
        'localnetwork': lambda opts: build_localnetwork(upstream_dir, opts, notes),
        'bt-direct': lambda opts: build_bt_direct(upstream_dir, opts, notes),
        'process-direct': lambda opts: build_process_direct(upstream_dir, opts, notes),
    }
    rule_sources = {
        'fake-ip-filter': [SOURCES['fake-ip-filter']],
        'localnetwork': [SOURCES['localnetwork-ipv4'], SOURCES['localnetwork-ipv6']],
        'bt-direct': [SOURCES['yml-rules-change']],
        'process-direct': [SOURCES['yml-rules-change']],
    }
    for name, build in builders.items():
        options = rule_options(config, name)
        if not options['enabled']:
            continue
        result = build(options)
        lines, kept = result[0], result[1]
        if name == 'fake-ip-filter':
            inline_filters = result[2]
        outputs[RULE_SETS[name]['path']] = render_rule_set(upstream, name, lines, rule_sources[name])
        rule_counts[name] = len(kept)
        used_sources.update(rule_sources[name])

    fragment_builders = [
        ('dns-servers', 'fragments/dns-servers.yaml', '上游 DNS 预设与兜底逻辑', build_dns_servers),
        ('fallback-filter', 'fragments/fallback-filter.yaml', 'dns.fallback-filter', build_fallback_filter),
        ('sniffer', 'fragments/sniffer.yaml', '域名嗅探', build_sniffer),
        ('hosts', 'fragments/hosts.yaml', '路由器常见主机名', build_hosts),
        ('ntp', 'fragments/ntp.yaml', '内核 NTP 对时', build_ntp),
        ('keep-alive', 'fragments/keep-alive.yaml', 'TCP keep-alive', build_keep_alive),
        ('geox-url', 'fragments/geox-url.yaml', 'GEO 数据源', build_geox_url),
    ]
    for name, path, title, build in fragment_builders:
        if not fragment_enabled(config, name):
            continue
        text, sources = build(upstream, upstream_dir)
        outputs[path] = text
        fragment_titles[path] = title
        used_sources.update(sources)

    if inline_filters:
        head = [
            'OpenClash 的 Fake-IP 过滤里有 geosite:/rule-set: 这类条目，只能写在 dns.fake-ip-filter 里，不能放进规则集',
            f"来源：{blob_url(upstream, SOURCES['fake-ip-filter'])}",
            GENERATED_NOTE,
        ]
        path = 'fragments/fake-ip-filter-inline.yaml'
        outputs[path] = comment_block(head) + '\n\n' + dump_yaml({'dns': {'fake-ip-filter': inline_filters}})
        fragment_titles[path] = 'Fake-IP 过滤里只能内联的条目'

    modules_option = config['fragments'].get('overwrite-modules', True)
    if fragment_enabled(config, 'overwrite-modules'):
        skip = set(modules_option.get('exclude') or []) if isinstance(modules_option, dict) else set()
        module_dir = upstream_dir / OVERWRITE_DIR
        if not module_dir.is_dir():
            raise ExtractError(f'上游缺少目录 {OVERWRITE_DIR}')
        for module in sorted(p.name for p in module_dir.iterdir() if p.is_file()):
            if module in skip:
                continue
            text, sources = build_module(upstream, upstream_dir, module)
            used_sources.update(sources)
            if text is None:
                continue
            path = f'fragments/overwrite-{module}.yaml'
            outputs[path] = text
            fragment_titles[path] = f'官方覆写模块 {module}'

    for rel, text in outputs.items():
        if rel.endswith('.yaml') and not isinstance(yaml.safe_load(text), dict):
            raise ExtractError(f'{rel}：生成的 YAML 不是映射')

    # The rule-sets and fragments are portions of OpenClash, its license travels with them.
    outputs['LICENSE'] = read(upstream_dir, SOURCES['license'])
    used_sources.add(SOURCES['license'])

    repo, branch = args.publish_repo, args.publish_branch
    outputs['config-example.yaml'] = build_example(repo, branch, list(rule_counts), inline_filters)
    outputs['README.md'] = build_readme(repo, branch, args.default_branch, upstream, rule_counts, fragment_titles)

    sha = git(upstream_dir, 'rev-parse', 'HEAD')
    previous = read_tree(args.previous)
    try:
        old_sources = json.loads(previous.get('SOURCES.json', '{}'))
    except json.JSONDecodeError:
        old_sources = {}
    old_sha = old_sources.get('upstream', {}).get('commit', '')
    changes = compare(previous, outputs)
    tracked = sorted(used_sources)
    commits, in_range = upstream_commits(upstream_dir, old_sha, sha, tracked)
    report = build_report(upstream, sha, old_sha, commits, in_range, changes, notes, not previous)

    outputs['CHANGELOG.md'] = merge_changelog(report, previous.get('CHANGELOG.md'))
    outputs['SOURCES.json'] = json.dumps({
        'upstream': {**upstream, 'commit': sha, 'commit_date': git(upstream_dir, 'log', '-1', '--format=%cI')},
        'generated_at': datetime.now(timezone.utc).isoformat(timespec='seconds'),
        'sources': {rel: hashlib.sha256((upstream_dir / rel).read_bytes()).hexdigest() for rel in tracked},
        'rule_sets': rule_counts,
    }, ensure_ascii=False, indent=2) + '\n'

    out = Path(args.out)
    if out.exists():
        shutil.rmtree(out)
    for rel, text in outputs.items():
        target = out / rel
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding='utf-8')
    if args.report:
        Path(args.report).write_text(report, encoding='utf-8')
    if args.commit_message:
        Path(args.commit_message).write_text(commit_message(upstream, sha, changes), encoding='utf-8')

    changed = bool(changes)
    if os.environ.get('GITHUB_OUTPUT'):
        with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as handle:
            handle.write(f"changed={'true' if changed else 'false'}\nupstream_sha={sha}\n")
    print(f"{'有变化' if changed else '无变化'}：{len(changes)} 个文件，上游 {sha[:7] if sha else 'unknown'}")
    for note in notes:
        print(f'备注：{note}')


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest='command', required=True)
    settings = sub.add_parser('settings')
    settings.add_argument('--config', required=True)
    sub.add_parser('paths')
    build = sub.add_parser('build')
    build.add_argument('--config', required=True)
    build.add_argument('--upstream', required=True, help='upstream OpenClash checkout')
    build.add_argument('--previous', help='checkout of the published presets branch')
    build.add_argument('--out', required=True)
    build.add_argument('--report', help='write the markdown change report here')
    build.add_argument('--commit-message', help='write the commit message here')
    build.add_argument('--publish-repo', default='Ayaka-KM/mihomo-presets')
    build.add_argument('--publish-branch', default='dist')
    build.add_argument('--default-branch', default='main')
    args = parser.parse_args()
    try:
        {'settings': cmd_settings, 'paths': cmd_paths, 'build': cmd_build}[args.command](args)
    except ExtractError as err:
        print(f'::error::{err}', file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()
