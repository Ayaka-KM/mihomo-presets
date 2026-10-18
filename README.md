# OpenClash 预设（供裸 mihomo 使用）

本分支由 [Ayaka-KM/mihomo-presets](https://github.com/Ayaka-KM/mihomo-presets/tree/main) 的工作流每天从 [vernesong/OpenClash@dev](https://github.com/vernesong/OpenClash/tree/dev) 自动提取生成，请勿手改。接入方法见 [`config-example.yaml`](config-example.yaml)，每次变化见 [`CHANGELOG.md`](CHANGELOG.md)。

## 规则集（mihomo 通过 rule-providers 自动更新）

| 文件 | behavior | 条目数 | 用法 |
|---|---|---|---|
| [`rules/fake-ip-filter.list`](https://raw.githubusercontent.com/Ayaka-KM/mihomo-presets/dist/rules/fake-ip-filter.list) | domain | 142 | 在 dns.fake-ip-filter 里写 rule-set:oc-fake-ip-filter 引用 |
| [`rules/localnetwork.list`](https://raw.githubusercontent.com/Ayaka-KM/mihomo-presets/dist/rules/localnetwork.list) | ipcidr | 23 | 在 tun.route-exclude-address-set 里引用，或写成 RULE-SET,oc-localnetwork,DIRECT,no-resolve |
| [`rules/bt-direct.list`](https://raw.githubusercontent.com/Ayaka-KM/mihomo-presets/dist/rules/bt-direct.list) | classical | 27 | 写成 RULE-SET,oc-bt-direct,DIRECT；有 GeoSite 数据时 OpenClash 优先改用 GEOSITE,category-public-tracker,DIRECT |

## 配置片段（需要手动合并）

| 文件 | 内容 |
|---|---|
| [`fragments/dns-servers.yaml`](fragments/dns-servers.yaml) | 上游 DNS 预设与兜底逻辑 |
| [`fragments/fallback-filter.yaml`](fragments/fallback-filter.yaml) | dns.fallback-filter |
| [`fragments/sniffer.yaml`](fragments/sniffer.yaml) | 域名嗅探 |
| [`fragments/hosts.yaml`](fragments/hosts.yaml) | 路由器常见主机名 |
| [`fragments/ntp.yaml`](fragments/ntp.yaml) | 内核 NTP 对时 |
| [`fragments/keep-alive.yaml`](fragments/keep-alive.yaml) | TCP keep-alive |
| [`fragments/geox-url.yaml`](fragments/geox-url.yaml) | GEO 数据源 |
| [`fragments/overwrite-Google_Play.yaml`](fragments/overwrite-Google_Play.yaml) | 官方覆写模块 Google_Play |
| [`fragments/overwrite-Tailscale.yaml`](fragments/overwrite-Tailscale.yaml) | 官方覆写模块 Tailscale |
| [`fragments/overwrite-WiFi_Calling.yaml`](fragments/overwrite-WiFi_Calling.yaml) | 官方覆写模块 WiFi_Calling |

## 许可

规则集和配置片段提取自 [vernesong/OpenClash](https://github.com/vernesong/OpenClash)，沿用其许可证，原文见 [`LICENSE`](LICENSE)。
