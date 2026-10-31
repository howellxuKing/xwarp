# Routing V3: built-in cloud rules for Clash Verge

User clarified on 2026-10-31: install the supplied Loyalsoldier rule-providers scheme into the GitHub project so fresh installs emit usable subscriptions without pasting YAML. This supersedes the initial inline-list V3 draft. After tests, publish via the normal immutable-image installer manifest. Do not deploy the live server or change the live client's mode/selections.

Acceptance:

1. Default subscriptions include HTTP domain provider direct and IP provider cncidr from the supplied testingcf.jsdelivr.net Loyalsoldier release URLs. Explicit yaml behavior/format, unique cache paths, 86400-second updates, proxy: PROXY for downloading through the selected node.
2. Local IPv4/IPv6 and local names use explicit built-in rules, not a cloud LAN set or broad GEOIP,lan. Preserve a short common-mainland baseline for QQ, Taobao, Alipay, JD, Bilibili, Baidu, Douyin and Jinritemai.
3. Order: local, manual exceptions, mainland baseline, RULE-SET,direct,DIRECT, RULE-SET,cncidr,DIRECT,no-resolve, MATCH,PROXY. No duplicated hidden critical-service proxy block. Exact duplicate rules removed. no-resolve only suppresses on-demand DNS for IP matching; it is not a DNS pollution cure or a perfect nationality classifier.
4. Advertising rejection defaults OFF. Do not download the optional large reject set unless an administrator explicitly enables/configures it later. The upstream direct classification is a maintained routing list, not a guarantee about corporate nationality.
5. Exactly one manual PROXY selector containing actual nodes. No automatic AUTO/FALLBACK groups or DIRECT member; no nodes uses REJECT. Historical template references to AUTO/FALLBACK map to PROXY to avoid dangling references.
6. Full provider templates no longer need the legacy inline-domestic marker. Still support already saved legacy marker templates using their cached inline data; stop default background inline-list downloads. Preserve valid custom templates. Known old built-in digests migrate to new default.
7. Validate mapping/rules shape, representative rule arity, provider references, one terminal MATCH,PROXY at the end, and reject invalid catch-all direct templates. Keep current no-resolve policy for CN GEOIP custom rules.
8. Preserve node authentication, certificates, quotas, login and network listeners; no frontend change. DNS remains client-managed; the browser/TUN muse.ai symptom is not claimed fixed merely because HTTP proxy probes or parser checks succeed.

Verification: Go unit/regression tests; real HTTP subscription acceptance for default providers, one selector, legacy edited templates, save/get/clear and invalid saves; actual installed Mihomo -t in an isolated temporary home with dummy node and preseeded tiny provider caches (no user config changes). Initial provider download/refresh depends on source reachability; offline first start is not guaranteed. Current non-ad provider data totals approximately 2.5 MB, replacing cached files rather than accumulating history.
