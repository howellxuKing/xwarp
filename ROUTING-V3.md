# Routing V3: explicit mainland/direct, other/proxy

User request (2026-10-31): replace the accumulated routing policy, preserving local/LAN direct, mainland services direct, other destinations proxy, and explicit administrator exceptions. Develop independently; do not change public main, installer pins or the running server/client as part of this candidate.

Acceptance:

1. One visible ordered rule template. Explicit private IPv4/IPv6 and local names direct. Do not use GEOIP,lan to broadly classify special-use/fake-IP ranges as local.
2. Manual exceptions keep their meaning; remove the hidden critical-service block prepended over administrator choices. Local destinations remain direct before manual domains.
3. Keep a short common-mainland domain baseline (QQ, Taobao, Alipay, JD, Bilibili and their known companion domains), followed by the existing bounded/cached domestic list. Keep a short visible overseas-service proxy baseline, including the reported muse.ai case, before domestic rules.
4. China-IP direct is a final supplemental rule with no-resolve: it must not trigger DNS solely for a routing guess. If destination information is insufficient, use MATCH,PROXY. This cannot identify every mainland-owned website perfectly.
5. One PROXY manual selector, containing actual nodes only. Do not silently default to AUTO, FALLBACK or DIRECT; no nodes uses REJECT rather than sending unmatched traffic direct.
6. Validate syntax and a single terminal MATCH,PROXY; report malformed/conflicting terminal policies at save time, preserve existing valid custom templates. Known historical built-in templates can migrate, including the immediately previous default.
7. No node credentials/listeners, quota, login, certificate, DNS or live client mode changes. Retain existing cached-list size/count limits and last-good behavior.

Tests at public seams: generated whole subscription HTTP fixture; offline domain-only routing examples (mainland, overseas, local, overrides), full YAML parsing, snapshot store recovery. Verify a candidate with the actual Mihomo binary independently of the user's live instance. A successful curl HTTP-proxy request is not proof a browser/TUN path works; report browser-specific findings separately.
