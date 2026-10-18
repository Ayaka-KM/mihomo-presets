# mihomo-presets

mihomo-presets：把 OpenClash 的预设同步给裸 mihomo。

OpenClash 根据多年来大量 issue 积累了很多"不踩坑想不到"的预设：Fake-IP 过滤、本地网段、DNS 兜底、嗅探例外等。本仓库的工作流每天从官方仓库提取这些预设，转换成裸 mihomo 能直接用的格式，用官方 mihomo 内核校验通过后发布到 [`dist`](https://github.com/Ayaka-KM/mihomo-presets/tree/dist) 分支。

## 流程

1. **触发**：北京时间每天 03:23 定时运行；也可以在 Actions 页面手动运行；修改 `config.yaml`、脚本或工作流并推送到 `main` 时也会运行。
2. **拉取**：克隆 `vernesong/OpenClash`（默认 `dev` 分支），只取出预设相关的文件。
3. **提取**：`extract.py` 生成产出，并和 `dist` 分支上已发布的版本对比；没变化就到此结束。
4. **校验**：有变化时，下载 [MetaCubeX/mihomo](https://github.com/MetaCubeX/mihomo/releases) 的最新正式版（linux-amd64-v1），由 `validate.py` 做三项检查：
   - `mihomo -t` 检查示例配置加上所有片段；
   - 启动内核，核对每个规则集"写入条数 = 内核实际加载条数"，确保没有条目被静默丢弃；
   - 通过内核的 DNS 实测 Fake-IP 过滤是否生效。
5. **发布**：校验通过后提交到 `dist` 分支。`CHANGELOG.md` 会记下这次新增、删除了哪些条目，以及对应的上游提交。

## 产出（`dist` 分支）

| 文件 | 来源（OpenClash） | 用法 |
|---|---|---|
| `rules/fake-ip-filter.list` | `custom/openclash_custom_fake_filter.list` | rule-provider（domain），在 `dns.fake-ip-filter` 写 `rule-set:oc-fake-ip-filter` |
| `rules/localnetwork.list` | `custom/openclash_custom_localnetwork_ipv4/ipv6.list` | rule-provider（ipcidr），给 `tun.route-exclude-address-set`，或写成 `RULE-SET,…,DIRECT,no-resolve` |
| `rules/bt-direct.list` | `yml_rules_change.sh` 的 BT/PT 规则 | `RULE-SET,oc-bt-direct,DIRECT` |
| `rules/process-direct.list`（默认关） | `yml_rules_change.sh` 的进程名规则 | `RULE-SET,oc-process-direct,DIRECT`，只对路由器本机进程有效 |
| `fragments/dns-servers.yaml` | `etc/config/openclash` 的 `dns_servers` + `yml_change.sh` 的兜底逻辑 | 手动合并 |
| `fragments/fallback-filter.yaml` | `custom/openclash_custom_fallback_filter.yaml` | 手动合并 |
| `fragments/sniffer.yaml` | `custom/openclash_custom_sniffer.yaml` | 手动合并 |
| `fragments/hosts.yaml`、`ntp.yaml`、`keep-alive.yaml` | `yml_change.sh` 里写死的默认值 | 手动合并 |
| `fragments/geox-url.yaml` | `etc/config/openclash` 的 GEO 数据源 | 手动合并 |
| `fragments/overwrite-*.yaml` | `etc/openclash/overwrite/*`（官方覆写模块） | 手动合并；OpenClash 的覆写操作符已展开成普通配置，文件头写明了合并方式 |
| `config-example.yaml` | — | 接入示例，里面是本仓库的实际地址 |

规则集是变化最频繁、条目最多的部分，交给 mihomo 自己定时拉取。片段很少变化，而 mihomo 没有 include 机制，所以需要手动合并；有变化时 `CHANGELOG.md` 会给出 diff。

## 在裸核里使用

按 `dist` 分支上的 `config-example.yaml` 把规则集接进自己的配置，比如：

```yaml
rule-providers:
  oc-fake-ip-filter:
    type: http
    behavior: domain
    format: text
    url: https://raw.githubusercontent.com/Ayaka-KM/mihomo-presets/dist/rules/fake-ip-filter.list
    path: ./ruleset/oc-fake-ip-filter.list
    interval: 86400

dns:
  fake-ip-filter:
    - rule-set:oc-fake-ip-filter
```

国内直连 `raw.githubusercontent.com` 可能不通，有两种办法：给 rule-provider 加 `proxy: <策略组>`，或者把地址换成 jsDelivr 镜像 `https://testingcf.jsdelivr.net/gh/Ayaka-KM/mihomo-presets@dist/rules/fake-ip-filter.list`。

想先审阅再生效的话，可以把 url 里的 `dist` 换成某次提交的 SHA，确认没问题后再手动更新。

## 按需取舍：`config.yaml`

- `upstream`：预设来源，默认是 `dev` 分支（最先收到修复）。想要更稳就改成 `master`。
- `validator`：校验用的内核，`release: latest` 是最新正式版。也可以锁定成和路由器一致的版本号，比如 `v1.19.32`。
- `rules.<名字>`：
  - `enabled` 开关；
  - `exclude` 按整行精确匹配去掉上游条目（比如嫌 `+.qq.com` 太宽）；
  - `include` 追加自己的条目，同样会经过格式校验。
- `fragments`：每个片段的开关；`overwrite-modules.exclude` 可以跳过不需要的官方模块。

改完推送到 `main`，工作流会立刻重新生成并发布。

## 本地运行

```sh
pip install pyyaml
git clone --filter=blob:none --no-checkout --branch dev https://github.com/vernesong/OpenClash.git upstream
python extract.py paths | git -C upstream sparse-checkout set --no-cone --stdin
git -C upstream checkout dev
python extract.py build --config config.yaml --upstream upstream --out out
python validate.py --mihomo /path/to/mihomo --out out \
  --mmdb upstream/luci-app-openclash/root/etc/openclash/Country.mmdb
```

## 通知与排错

- **运行失败**：GitHub 会发邮件。定时任务的失败通知发给最后修改 cron 那一行的人；如果收不到，在网页上编辑一下这一行再提交即可。
  - 上游改写了相关代码、导致提取不到时，任务会失败并说明是哪一项，此时不会发布任何东西，需要相应更新 `extract.py` 里的匹配规则。
  - 校验失败时，运行摘要里会列出内核报的错误。
- **关注变化**：订阅 `https://github.com/Ayaka-KM/mihomo-presets/commits/dist.atom`，每次发布都有一条，提交说明里写着改了哪些条目。
- **定时停用**：公开仓库连续 60 天没有活动时，GitHub 会自动停用定时任务，到 Actions 页面重新启用即可。

## 局限

- 只同步数据，不复制 OpenClash 的运行时逻辑：DNS 防回环检查、防火墙规则、dnsmasq 联动、流媒体解锁检测都不在其中。
- 通过匹配代码提取的项（hosts、NTP、keep-alive、DNS 兜底、BT/PT 规则）依赖上游的写法，上游重构时需要跟着调整。
- 片段需要手动合并。
