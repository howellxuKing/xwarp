# Custom subscription rules correction

Reported behavior: adding https://0996zp.com/ to the direct website list may make nodes appear disconnected after a client refreshes its subscription.

Acceptance requirements:

- Saving direct/proxy website lists must produce a valid Clash YAML subscription.
- Custom proxy rules precede custom direct rules, both inside the single rules sequence and before existing base rules.
- Preserve node definitions, proxy groups, and administrator base configuration fields.
- Keep existing URL normalization (https://0996zp.com/ becomes 0996zp.com), empty lists, clearing lists, and editable base rule templates working.
- Do not change server listeners, node authentication, traffic quotas, registration, or live deployments.
- Reproduce through the existing API fixture before correction; verify YAML merging with an isolated Go package and exercise save/get/clear through real HTTP acceptance.
