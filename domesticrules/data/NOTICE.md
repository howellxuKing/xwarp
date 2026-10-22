# Third-party domestic routing data

domestic.list is an unmodified text snapshot of MetaCubeX/meta-rules-dat:
https://github.com/MetaCubeX/meta-rules-dat/blob/5b62abd872efea28a44ee1ec0dc3869cff27c739/geo/geosite/geolocation-cn.list

Source commit: 5b62abd872efea28a44ee1ec0dc3869cff27c739.
Source project: https://github.com/MetaCubeX/meta-rules-dat
License: GNU GPL version 3 (see LICENSE). The upstream project credits v2fly/domain-list-community and other sources in its README. This snapshot uses geolocation-cn rather than the much larger cn aggregate. XWarp converts entries to ordinary Clash domain rules at runtime; it does not require an MRS-capable client.

Runtime updates use the same project's meta branch path, validate the entire response and identify each accepted snapshot by SHA-256. Preserve this notice and license when redistributing the data.
