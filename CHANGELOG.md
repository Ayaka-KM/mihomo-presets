# 变化记录

## 2026-11-06 08:25（北京时间）

上游 [vernesong/OpenClash@dev](https://github.com/vernesong/OpenClash/tree/dev)：[`c5c7bfa`](https://github.com/vernesong/OpenClash/commit/c5c7bfa6cbd675c2ed0ae53ccffdd6bf30321825) → [`c6484df`](https://github.com/vernesong/OpenClash/commit/c6484df2fb90d782d8578b5f9ad229881d736ef1)

### 上游相关提交

- [`c6484df`](https://github.com/vernesong/OpenClash/commit/c6484df2fb90d782d8578b5f9ad229881d736ef1) 2026-11-05 chore: refine

### 产出变化

- `fragments/overwrite-Tailscale.yaml`：有改动

<details><summary>diff</summary>

```diff
--- published
+++ new
@@ -1,10 +1,11 @@
 # OpenClash 官方覆写模块：Tailscale
 # 来源：https://github.com/vernesong/OpenClash/blob/dev/luci-app-openclash/root/etc/openclash/overwrite/Tailscale
-# 说明：Tailscale MagicDNS: resolve ts.net names through the Tailscale DNS stub
+# 说明：Tailscale MagicDNS and DERP names bypass the fake-ip pool
 # 原注释：
-#   Tailscale MagicDNS: resolve ts.net names through the Tailscale DNS stub, the public DNS does
-#   not know them. Requires tailscaled to be running.
+#   tailscaled must be running: ts.net only resolves through its stub, and a fake-ip answer
+#   makes the client dial a pool address it cannot reach
 # 合并方式（原模块用 OpenClash 的覆写操作符，这里已展开成普通配置）：
 #   dns.nameserver-policy：合并进你已有的映射（原写法 nameserver-policy+）
+#   dns.fake-ip-filter：追加到你已有列表的末尾（原写法 fake-ip-filter+）
 # 由 mihomo-presets 工作流自动生成，请勿手改；按需取舍请改仓库默认分支上的 config.yaml
 
@@ -13,2 +14,5 @@
     +.ts.net:
     - 100.100.100.100#DIRECT
+  fake-ip-filter:
+  - +.tailscale.com
+  - +.ts.net
```

</details>

## 2026-11-04 13:12（北京时间）

上游 [vernesong/OpenClash@dev](https://github.com/vernesong/OpenClash/tree/dev)：[`4e668a0`](https://github.com/vernesong/OpenClash/commit/4e668a098f061a936897dd89226b2ae03d0c2444) → [`c5c7bfa`](https://github.com/vernesong/OpenClash/commit/c5c7bfa6cbd675c2ed0ae53ccffdd6bf30321825)

### 上游相关提交

- [`2d55ea0`](https://github.com/vernesong/OpenClash/commit/2d55ea07932de24318741403571531dbe46c034b) 2026-11-02 chore: add DDNS module

### 产出变化

- `README.md`：随上面的变化重新生成
- `config-example.yaml`：随上面的变化重新生成
- `fragments/overwrite-BT_PT_Download.yaml`：有改动

<details><summary>diff</summary>

```diff
--- published
+++ new
@@ -6,5 +6,5 @@
 #   rules：追加到你已有列表的末尾（原写法 rules+）
 #   rules：原写法 rules* 是批量修改操作，没法变成静态片段，已跳过
-# 占位符 PT_SITE 已替换为默认值 your-pt-site.invalid，按需改成你自己的策略组
+# 占位符 PT_SITE 已替换为默认值 your-pt-site.invalid，按需改成你自己的值
 # 插件设置（[General]，是 OpenClash 自身的开关，裸核里没有，仅供参考）：
 #   EN_MODE = redir-host
```

</details>

- `fragments/overwrite-DDNS.yaml`：新增文件

## 2026-11-02 03:54（北京时间）

上游 [vernesong/OpenClash@dev](https://github.com/vernesong/OpenClash/tree/dev)：[`91d7370`](https://github.com/vernesong/OpenClash/commit/91d73707a6bcd0f8ec96a57095d72b1b4357cbe7) → [`4e668a0`](https://github.com/vernesong/OpenClash/commit/4e668a098f061a936897dd89226b2ae03d0c2444)

### 上游相关提交

- [`4e668a0`](https://github.com/vernesong/OpenClash/commit/4e668a098f061a936897dd89226b2ae03d0c2444) 2026-11-02 chore: refine
- [`19d5e86`](https://github.com/vernesong/OpenClash/commit/19d5e86908dd220617e23f64870b61aba8787777) 2026-11-02 chore: add BT_PT_Download module
- [`73f3abd`](https://github.com/vernesong/OpenClash/commit/73f3abdb8d4ef46ea939b1b9c730f13d3e800d5b) 2026-10-26 chore: bugs fix
- [`ae9369c`](https://github.com/vernesong/OpenClash/commit/ae9369c8cd711dc9e439a37f6f316bed01242b32) 2026-10-20 chore: config subscribe config option

### 产出变化

- `README.md`：随上面的变化重新生成
- `fragments/overwrite-BT_PT_Download.yaml`：新增文件

## 2026-10-19 03:30（北京时间）

上游 [vernesong/OpenClash@dev](https://github.com/vernesong/OpenClash/tree/dev)：[`91d7370`](https://github.com/vernesong/OpenClash/commit/91d73707a6bcd0f8ec96a57095d72b1b4357cbe7)

### 上游最近的相关提交

- [`fd81d97`](https://github.com/vernesong/OpenClash/commit/fd81d97822077d5cd246c691813cf5ee5eba752d) 2026-10-15 chore: add disable_tun_gso option
- [`b934bd2`](https://github.com/vernesong/OpenClash/commit/b934bd28e97d3685083bfe3bd0a7a7e9b4c66d5d) 2026-10-15 chore: bridge-nf-call-iptables setting
- [`0201d30`](https://github.com/vernesong/OpenClash/commit/0201d30f8ea54127e5d75e2007c2e747f5f8d22f) 2026-10-14 chore: refine style
- [`407ebe4`](https://github.com/vernesong/OpenClash/commit/407ebe4c3a33983072b2dd6a1ea34e8f97632121) 2026-10-10 chore: refine style
- [`f760b44`](https://github.com/vernesong/OpenClash/commit/f760b44396df32306ea33cf312b7ec20ac745f4e) 2026-10-09 chore: add Tailscale & WiFi_Calling module
- [`7144dd6`](https://github.com/vernesong/OpenClash/commit/7144dd666dec08c6394274f55e1ea61ffcee5708) 2026-10-08 0.47.171
- [`588cec5`](https://github.com/vernesong/OpenClash/commit/588cec56111c6f54a1ae24a4b848afbecc1a2f7f) 2026-10-03 chore: refine codes
- [`61ac74d`](https://github.com/vernesong/OpenClash/commit/61ac74d3f15d5040a8c618791196a4843b2483f2) 2026-09-30 0.47.168
- [`ab01711`](https://github.com/vernesong/OpenClash/commit/ab017113a1457d89279508a45a35d0bfb8d345f0) 2026-09-29 chore: refine
- [`be17bdb`](https://github.com/vernesong/OpenClash/commit/be17bdbd24cebda4f09eab2e2c35e9fec1c30caa) 2026-09-27 chore: enable gso for tun

### 产出变化

- `LICENSE`：新增文件
- `README.md`：随上面的变化重新生成

## 2026-10-19 03:14（北京时间）

上游 [vernesong/OpenClash@dev](https://github.com/vernesong/OpenClash/tree/dev)：[`91d7370`](https://github.com/vernesong/OpenClash/commit/91d73707a6bcd0f8ec96a57095d72b1b4357cbe7)

### 上游最近的相关提交

- [`fd81d97`](https://github.com/vernesong/OpenClash/commit/fd81d97822077d5cd246c691813cf5ee5eba752d) 2026-10-15 chore: add disable_tun_gso option
- [`b934bd2`](https://github.com/vernesong/OpenClash/commit/b934bd28e97d3685083bfe3bd0a7a7e9b4c66d5d) 2026-10-15 chore: bridge-nf-call-iptables setting
- [`0201d30`](https://github.com/vernesong/OpenClash/commit/0201d30f8ea54127e5d75e2007c2e747f5f8d22f) 2026-10-14 chore: refine style
- [`407ebe4`](https://github.com/vernesong/OpenClash/commit/407ebe4c3a33983072b2dd6a1ea34e8f97632121) 2026-10-10 chore: refine style
- [`f760b44`](https://github.com/vernesong/OpenClash/commit/f760b44396df32306ea33cf312b7ec20ac745f4e) 2026-10-09 chore: add Tailscale & WiFi_Calling module
- [`7144dd6`](https://github.com/vernesong/OpenClash/commit/7144dd666dec08c6394274f55e1ea61ffcee5708) 2026-10-08 0.47.171
- [`588cec5`](https://github.com/vernesong/OpenClash/commit/588cec56111c6f54a1ae24a4b848afbecc1a2f7f) 2026-10-03 chore: refine codes
- [`61ac74d`](https://github.com/vernesong/OpenClash/commit/61ac74d3f15d5040a8c618791196a4843b2483f2) 2026-09-30 0.47.168
- [`ab01711`](https://github.com/vernesong/OpenClash/commit/ab017113a1457d89279508a45a35d0bfb8d345f0) 2026-09-29 chore: refine
- [`be17bdb`](https://github.com/vernesong/OpenClash/commit/be17bdbd24cebda4f09eab2e2c35e9fec1c30caa) 2026-09-27 chore: enable gso for tun

### 首次发布

- `README.md`：新增文件
- `config-example.yaml`：新增文件
- `fragments/dns-servers.yaml`：新增文件
- `fragments/fallback-filter.yaml`：新增文件
- `fragments/geox-url.yaml`：新增文件
- `fragments/hosts.yaml`：新增文件
- `fragments/keep-alive.yaml`：新增文件
- `fragments/ntp.yaml`：新增文件
- `fragments/overwrite-Google_Play.yaml`：新增文件
- `fragments/overwrite-Tailscale.yaml`：新增文件
- `fragments/overwrite-WiFi_Calling.yaml`：新增文件
- `fragments/sniffer.yaml`：新增文件
- `rules/bt-direct.list`：新增文件
- `rules/fake-ip-filter.list`：新增文件
- `rules/localnetwork.list`：新增文件
