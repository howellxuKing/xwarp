package constant

// ClashRulesV233SHA256 identifies the unmodified v2.3.3 default rule template.
// It lets upgrades adopt the new defaults without overwriting administrator-customized rules.
const ClashRulesV233SHA256 = "d6d8f54a5cd95bd0a1c3e9beead79506b3460da489d535ff92bb903cb2959718"

// ClashRulesPreviousSHA256 identifies the unmodified v2.3.4 default rule template.
const ClashRulesPreviousSHA256 = "de6de67fc342191241e375f96b56cf81659a80f59237b624873be7326783e9d4"

// ClashRulesV250SHA256 identifies the unmodified v2.5.0 default template, which still placed
// GEOIP,CN,DIRECT before the explicit overseas rules and therefore sent some overseas traffic direct.
const ClashRulesV250SHA256 = "21a3f7773ada01af31bb4a407a857082673150ef93d119afc06b90a42dfffbcf"

// ClashDomesticMarker is the placeholder line that the backend expands into the mainland domain
// block at subscription time. Administrator templates must keep this line; without it the
// mainland domains silently stop being routed direct.
const ClashDomesticMarker = "@XWARP-DOMESTIC@"

// ClashRules 订阅返回的 Clash 规则（自包含、无外部 rule-provider 依赖，Clash Verge 可直接导入）
//
// 分流模型：本地/内网直连 → 少量强制代理例外 → 国外下载类例外直连 → 中国大陆域名直连
// → 中国大陆 IP 直连（仅 IP 直连流量）→ 其余全部代理。
// 域名维度优先于 IP 维度，避免“国外服务解析到国内 IP 就被直连”这类误判。
const ClashRules = `rules:
  # 1. 本地网络、私人网段与常用国内 DNS 直连
  - GEOIP,private,DIRECT,no-resolve
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR6,::1/128,DIRECT,no-resolve
  - IP-CIDR6,fc00::/7,DIRECT,no-resolve
  - IP-CIDR6,fe80::/10,DIRECT,no-resolve
  - IP-CIDR,223.5.5.5/32,DIRECT,no-resolve
  - IP-CIDR,119.29.29.29/32,DIRECT,no-resolve
  - IP-CIDR,180.76.76.76/32,DIRECT,no-resolve
  - DOMAIN,localhost,DIRECT
  - DOMAIN-SUFFIX,local,DIRECT
  - DOMAIN-SUFFIX,lan,DIRECT

  # 2. 必须走代理的例外（必须排在中国大陆直连之前）
  - DOMAIN-SUFFIX,openai.com,PROXY
  - DOMAIN-SUFFIX,chatgpt.com,PROXY
  - DOMAIN-SUFFIX,oaistatic.com,PROXY
  - DOMAIN-SUFFIX,oaiusercontent.com,PROXY
  - DOMAIN-SUFFIX,anthropic.com,PROXY
  - DOMAIN-SUFFIX,claude.ai,PROXY
  - DOMAIN-SUFFIX,google.com,PROXY
  - DOMAIN-SUFFIX,googleapis.com,PROXY
  - DOMAIN-SUFFIX,gstatic.com,PROXY
  - DOMAIN-SUFFIX,googlevideo.com,PROXY
  - DOMAIN-SUFFIX,ggpht.com,PROXY
  - DOMAIN-SUFFIX,youtube.com,PROXY
  - DOMAIN-SUFFIX,youtu.be,PROXY
  - DOMAIN-SUFFIX,ytimg.com,PROXY
  - DOMAIN-SUFFIX,youtube-nocookie.com,PROXY
  - DOMAIN-SUFFIX,github.com,PROXY
  - DOMAIN-SUFFIX,githubassets.com,PROXY
  - DOMAIN-SUFFIX,githubusercontent.com,PROXY
  - DOMAIN-SUFFIX,telegram.org,PROXY
  - DOMAIN-SUFFIX,t.me,PROXY
  - DOMAIN-SUFFIX,twitter.com,PROXY
  - DOMAIN-SUFFIX,twimg.com,PROXY
  - DOMAIN-SUFFIX,x.com,PROXY

  # 3. 国外域名但希望直连：游戏下载与系统更新，避免走代理消耗流量
  - DOMAIN-SUFFIX,steamcontent.com,DIRECT
  - DOMAIN-SUFFIX,steamserver.net,DIRECT
  - DOMAIN-SUFFIX,cm.steampowered.com,DIRECT
  - DOMAIN-SUFFIX,epgames.com,DIRECT

  # 4. 中国大陆域名直连（下一行是占位符，订阅时展开为 geolocation-cn 域名块）
  # @XWARP-DOMESTIC@
  - GEOIP,cn,DIRECT,no-resolve

  # 5. 兜底：其余全部走代理
  - MATCH,PROXY
`
