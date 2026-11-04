package constant

// ClashRulesV233SHA256 identifies the unmodified v2.3.3 default rule template.
// It lets upgrades adopt the new defaults without overwriting administrator-customized rules.
const ClashRulesV233SHA256 = "d6d8f54a5cd95bd0a1c3e9beead79506b3460da489d535ff92bb903cb2959718"

// ClashRulesPreviousSHA256 identifies the unmodified v2.3.4 default rule template.
const ClashRulesPreviousSHA256 = "de6de67fc342191241e375f96b56cf81659a80f59237b624873be7326783e9d4"

// ClashRulesV250SHA256 identifies the unmodified v2.5.0 default template, which still placed
// GEOIP,CN,DIRECT before the explicit overseas rules and therefore sent some overseas traffic direct.
const ClashRulesV250SHA256 = "21a3f7773ada01af31bb4a407a857082673150ef93d119afc06b90a42dfffbcf"

// ClashRulesV251SHA256 identifies the unmodified v2.5.1 default template. It carried two defects:
// GEOIP,private never matches in mihomo (only "lan" is special-cased), and GEOIP,cn,DIRECT,no-resolve
// can never match a domain connection, so every mainland domain outside the inline list fell through
// to MATCH,PROXY and went overseas.
// The digest is computed over the canonical form (CRLF normalized to LF, surrounding whitespace
// trimmed). v2.5.2 shipped it as a CRLF digest, which never matched, so installs that had saved the
// unmodified v2.5.1 template kept the broken rules after upgrading.
const ClashRulesV251SHA256 = "e6865ea8911b6b0465c3f21167912e5155f8bd3c85e886ac5fad048f4122112d"

// ClashRulesV252SHA256 identifies the unmodified v2.5.2 and v2.5.3 default template (identical text).
const ClashRulesV252SHA256 = "c4fbbad7b4038d9e4eacb8727f3dbd09b57cbf9d0d5ebd58ae263632d9a8ce70"

// ClashRulesV254SHA256 identifies the unmodified v2.5.4 default template, the first one that keeps
// GEOIP,cn on no-resolve so a foreign domain can never be matched by its resolved IP.
const ClashRulesV254SHA256 = "63615e724059803f6394ed014c8bb949bcc01c4596f5cd884201981a089d3a80"
const ClashRulesV255SHA256 = "ae932dd94ae01c27612f6e13ea11705ffe0b0fe5ca69780751617a592e2bc4ef"

// Domestic domains are expanded locally at subscription generation.
const ClashDomesticMarker = "@XWARP-DOMESTIC@"

// ClashRulesV3SHA256 identifies the v2.5.5-v2.5.7 cloud rule template. It still let
// every IPv6 destination through, which broke apps on clients whose line has no IPv6
// egress while the TUN interface still advertises IPv6.
const ClashRulesV3SHA256 = "4b66b991d912086d89633e1401b7f706a908f5a18d4a773326647a33324bc92c"

// ClashRulesV4SHA256 identifies the current template, the first one that rejects IPv6
// beyond the local ranges.
const ClashRulesV4SHA256 = "2f1cc27d645fa108bd7bd48c364301ffa5d0d1f217fe0e38530247581cfaaccd"

// Explicit local ranges only; fake-IP benchmark ranges are not LAN.
const ClashIPv6LocalRule = "AND,((IP-CIDR6,fc00::/7,no-resolve),(NOT,((IP-CIDR6,fdfe:dcba:9876::/64,no-resolve)))),DIRECT"

// ClashIPv6NoEgressRule turns "IPv6 exists on the interface but not on the line" into a
// fast failure instead of a hang.
//
// A TUN client still hands IPv6 addresses to applications when the node has no IPv6
// uplink. Chat apps then open a file transfer over IPv6, the packets leave through TUN
// and never come back, and the user sees "sending interrupted" while small messages
// (IPv4) keep working. Rejecting IPv6 beyond the local ranges makes the app retry over
// IPv4 immediately. Deployments that do have IPv6 can place IP-CIDR6,::/0,PROXY (or
// DIRECT) above this line to override it.
const ClashIPv6NoEgressRule = "IP-CIDR6,::/0,REJECT"

const ClashLocalRules = `  - DOMAIN,localhost,DIRECT
  - DOMAIN-SUFFIX,local,DIRECT
  - DOMAIN-SUFFIX,lan,DIRECT
  - IP-CIDR,127.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR6,::1/128,DIRECT,no-resolve
` + "  - " + ClashIPv6LocalRule + "\n" + `
  - IP-CIDR6,fe80::/10,DIRECT,no-resolve
`

// V3 cloud rule sets for Clash Verge/Mihomo. Cache files are replaced daily.
const ClashRules = `rule-providers:
  direct:
    type: http
    behavior: domain
    format: yaml
    interval: 86400
    proxy: PROXY
    path: ./ruleset/xwarp-direct.yaml
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/direct.txt
  cncidr:
    type: http
    behavior: ipcidr
    format: yaml
    interval: 86400
    proxy: PROXY
    path: ./ruleset/xwarp-cncidr.yaml
    url: https://testingcf.jsdelivr.net/gh/Loyalsoldier/clash-rules@release/cncidr.txt

rules:
` + ClashLocalRules + "  - " + ClashIPv6NoEgressRule + `
  # 手动网站例外在本地规则之后生效。广告拦截默认关闭。
  # 常用国内站点保底，完整分类由下面的规则集维护。
  - DOMAIN-SUFFIX,qq.com,DIRECT
  - DOMAIN-SUFFIX,taobao.com,DIRECT
  - DOMAIN-SUFFIX,alipay.com,DIRECT
  - DOMAIN-SUFFIX,jd.com,DIRECT
  - DOMAIN-SUFFIX,bilibili.com,DIRECT
  - DOMAIN-SUFFIX,baidu.com,DIRECT
  - DOMAIN-SUFFIX,douyin.com,DIRECT
  - DOMAIN-SUFFIX,jinritemai.com,DIRECT
  - RULE-SET,direct,DIRECT
  - RULE-SET,cncidr,DIRECT,no-resolve
  - MATCH,PROXY
`
