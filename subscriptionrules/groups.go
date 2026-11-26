package subscriptionrules

import (
	"fmt"

	"trojan-panel/model/bo"
)

const (
	// healthCheckURL is the generate_204 probe shared by the automatic groups.
	healthCheckURL = "https://www.gstatic.com/generate_204"

	// autoInterval re-ranks latency. Five minutes is enough for that, and it is
	// the interval AUTO already uses.
	autoInterval = 300

	// fallbackInterval is the failover bound, in seconds.
	//
	// Clash and Mihomo fallback do not switch when a TCP dial fails. They keep
	// the current member until a health check reports it down, so this interval
	// is how long a dead node can stay selected. 60s is five times sooner than
	// AUTO's five-minute rank: a downed node is left within about a minute.
	// It stays conservative: one small request per node per minute while the
	// group is in use, not a tight loop that would flap on a single slow probe.
	fallbackInterval = 60
)

// ProxyGroups preserves manual selection, offers automatic latency selection,
// and offers ordered failover. Routing rules keep targeting PROXY. FALLBACK is
// only a choice inside that selector, so the default member stays the first node.
// With no nodes the selector is REJECT and neither automatic group is emitted.
func ProxyGroups(nodes []string) []bo.ProxyGroup {
	if len(nodes) == 0 {
		return []bo.ProxyGroup{{Name: "PROXY", Type: "select", Proxies: []string{"REJECT"}}}
	}
	autoName := uniqueGroupName("AUTO", nodes)
	fallbackName := uniqueGroupName("FALLBACK", nodes)
	manual := make([]string, 0, len(nodes)+2)
	manual = append(manual, nodes...)
	manual = append(manual, autoName, fallbackName)
	return []bo.ProxyGroup{
		{Name: "PROXY", Type: "select", Proxies: manual},
		{Name: autoName, Type: "url-test", Proxies: append([]string{}, nodes...), Url: healthCheckURL, Interval: autoInterval},
		{Name: fallbackName, Type: "fallback", Proxies: append([]string{}, nodes...), Url: healthCheckURL, Interval: fallbackInterval},
	}
}

// uniqueGroupName returns base, then base-2, base-3, ... until the name is not
// one of the node names. Callers check each automatic group on its own, the
// same way AUTO has always avoided a node that is itself named AUTO.
func uniqueGroupName(base string, nodes []string) string {
	name := base
	for suffix := 2; ; suffix++ {
		if !nameIn(nodes, name) {
			return name
		}
		name = fmt.Sprintf("%s-%d", base, suffix)
	}
}

func nameIn(nodes []string, name string) bool {
	for _, node := range nodes {
		if node == name {
			return true
		}
	}
	return false
}
