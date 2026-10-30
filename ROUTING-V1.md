# Conservative mainland routing version 1

Scope: use a bundled, attributed MetaCubeX meta-rules-dat geolocation-cn text snapshot (~5,400 domains) and server-side daily refresh, not client-side providers. Preserve unknown->PROXY, explicit foreign-service rules, existing nodes/credentials/listeners/DNS, and administrator custom templates. No live deployment.

Rules: private IPv4/IPv6 and local names first in defaults; existing explicit foreign proxy rules before automatic domestic domains; domestic domains before GEOIP,CN; MATCH,PROXY remains last. Existing explicit administrator lists retain priority. Personal built-in 0996zp.com moves to administrator responsibility rather than global policy.

Updates: bounded HTTPS fetch to a fixed upstream, validate size/count/domain syntax; deduplicate; hash version; write snapshot atomically before activating. Explicit foreign rules stay before automatic domestic rules. Retain in-memory and disk last-good snapshot on HTTP/parse/write failure. On restart use valid disk snapshot or bundled baseline. Fetch off request path and never block startup/subscriptions on external connectivity. A fresh successful cache avoids startup refresh; scheduled retries run every 24 hours. XWARP_DISABLE_RULE_UPDATES=1 disables background updates (used in isolated CI).

Only current built-in templates (including the prior built-in SHA) adopt the new default. Saved administrator templates retain their previous contents; do not silently replace them.

Verification seams: complete HTTP subscription fixture (country/domain ordering, editable templates, node/group preservation), and public snapshot store (offline startup, persistence, failed update/restart, malformed/oversized input, concurrent reads). Use these established subscription/API test paths without requiring user platform interaction. No guarantee of every domestic domain, DNS improvements, or Shadowrocket rule compatibility in this version.

Third-party source: https://github.com/MetaCubeX/meta-rules-dat ; bundled data commit 5b62abd872efea28a44ee1ec0dc3869cff27c739, geo/geosite/geolocation-cn.list; GPL-3.0 text and attribution accompany data. Output plain DOMAIN/DOMAIN-SUFFIX entries, not MRS.

Single-label suffixes (including upstream brand TLD entries) are deliberately omitted, rather than making a whole top-level domain direct. The source snapshot itself is retained unchanged apart from a final newline.

## Routing v2（当前默认模板）

模型从「国外域名白名单 + GEOIP 抢域名」改为「默认代理、只放行大陆与内网」：

本地/内网直连 → 少量强制代理例外 → 国外下载类例外直连 → 大陆域名直连 → 大陆 IP 直连（含域名解析结果）→ 其余代理。

- 域名维度优先：大陆域名由模板里的占位行 `# @XWARP-DOMESTIC@` 展开，位置固定在 `GEOIP,cn,DIRECT` 之前，不再依赖字符串匹配 `GEOIP,CN,DIRECT` 的缩进；
- `GEOIP,cn,DIRECT` 不能带 `no-resolve`：带了之后域名连接不做解析，该规则永远匹配不到，未列入内联表的大陆站点会落到 `MATCH,PROXY` 绕道国外（v2.5.1 的实际缺陷，v2.5.2 修复）；
- 内网判定用 `GEOIP,lan`，不是 `GEOIP,private`：mihomo 只对 `lan` 做特殊处理，`private` 在 `geodata-mode: true` 下会让整份配置加载失败；
- 管理员自定义模板同样会展开该占位行；缺少占位行时保存会被拒绝，订阅侧记录告警并退回原模板（不再静默丢规则）；
- `XWARP_CLASH_GEOSITE=1` 时展开为单条 `GEOSITE,geolocation-cn,DIRECT`（仅适用 Mihomo / Clash Verge Rev，可省掉约 200KB 内联域名）；
- 订阅额外输出 `mode: rule`，代理组改为 `PROXY(select) / AUTO(url-test) / FALLBACK`；
- v2.3.3、v2.3.4、v2.5.0、v2.5.1 的未修改默认模板按摘要识别后自动升级到新默认；管理员修改过的模板保持不变。

显式例外只保留两类：必须走代理的国外服务（google/youtube/github/openai/telegram 等），以及希望直连的国外下载与更新域名（steam/windowsupdate 等）。

## Routing v2.5.3（关键服务强制代理）

v2.5.2 之后仍然出现「规则模式连不上 YouTube、全局模式正常」，原因有两层，都在 v2.5.3 修掉：

- **关键服务不再受模板影响**：订阅在拼接规则时，先把一段「必须走代理」的例外块插到最前面（`constant.ClashCriticalProxyRules`），再拼管理员自定义域名，最后才是模板。规则是「先匹配先赢」，所以即使模板是从第三方规则项目抄来的（开头 `GEOIP,cn,DIRECT`、结尾 `MATCH,DIRECT`），YouTube/Google/GitHub/OpenAI/Telegram 依然走 `PROXY`；
- **v2.5.1 的默认模板摘要算错了**：`ClashRulesV251SHA256` 当初按 CRLF、未裁剪的文本计算，而运行时按「CRLF 归一为 LF + 去首尾空白」计算，两者永远不相等。结果是「保存过默认模板」的安装升级到 v2.5.2 后仍然用着 v2.5.1 的旧规则。v2.5.3 改成统一的 `CanonicalDigest`，并补上 `ClashRulesV252SHA256`。

v2.5.3 起，订阅规则的第一条固定是 `DOMAIN-SUFFIX,openai.com,PROXY`，任何管理员模板都无法把它或后面的 YouTube 规则顶掉。

