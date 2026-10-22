# Conservative mainland routing version 1

Scope: use a bundled, attributed MetaCubeX meta-rules-dat geolocation-cn text snapshot (~5,400 domains) and server-side daily refresh, not client-side providers. Preserve unknown->PROXY, explicit foreign-service rules, existing nodes/credentials/listeners/DNS, and administrator custom templates. No live deployment.

Rules: private IPv4/IPv6 and local names first in defaults; existing explicit foreign proxy rules before automatic domestic domains; domestic domains before GEOIP,CN; MATCH,PROXY remains last. Existing explicit administrator lists retain priority. Personal built-in 0996zp.com moves to administrator responsibility rather than global policy.

Updates: bounded HTTPS fetch to a fixed upstream, validate size/count/domain syntax; deduplicate; hash version; write snapshot atomically before activating. Explicit foreign rules stay before automatic domestic rules. Retain in-memory and disk last-good snapshot on HTTP/parse/write failure. On restart use valid disk snapshot or bundled baseline. Fetch off request path and never block startup/subscriptions on external connectivity. A fresh successful cache avoids startup refresh; scheduled retries run every 24 hours. XWARP_DISABLE_RULE_UPDATES=1 disables background updates (used in isolated CI).

Only current built-in templates (including the prior built-in SHA) adopt the new default. Saved administrator templates retain their previous contents; do not silently replace them.

Verification seams: complete HTTP subscription fixture (country/domain ordering, editable templates, node/group preservation), and public snapshot store (offline startup, persistence, failed update/restart, malformed/oversized input, concurrent reads). Use these established subscription/API test paths without requiring user platform interaction. No guarantee of every domestic domain, DNS improvements, or Shadowrocket rule compatibility in this version.

Third-party source: https://github.com/MetaCubeX/meta-rules-dat ; bundled data commit 5b62abd872efea28a44ee1ec0dc3869cff27c739, geo/geosite/geolocation-cn.list; GPL-3.0 text and attribution accompany data. Output plain DOMAIN/DOMAIN-SUFFIX entries, not MRS.

Single-label suffixes (including upstream brand TLD entries) are deliberately omitted, rather than making a whole top-level domain direct. The source snapshot itself is retained unchanged apart from a final newline.
