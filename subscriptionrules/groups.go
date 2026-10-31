package subscriptionrules

import (
	"fmt"
	"trojan-panel/model/bo"
)

// ProxyGroups preserves manual selection and offers automatic latency selection.
func ProxyGroups(nodes []string) []bo.ProxyGroup {
	if len(nodes) == 0 {
		return []bo.ProxyGroup{{Name: "PROXY", Type: "select", Proxies: []string{"REJECT"}}}
	}
	autoName := "AUTO"
	for suffix := 2; ; suffix++ {
		collision := false
		for _, name := range nodes {
			if name == autoName {
				collision = true
				break
			}
		}
		if !collision {
			break
		}
		autoName = fmt.Sprintf("AUTO-%d", suffix)
	}
	manual := append(append([]string{}, nodes...), autoName)
	return []bo.ProxyGroup{
		{Name: "PROXY", Type: "select", Proxies: manual},
		{Name: autoName, Type: "url-test", Proxies: append([]string{}, nodes...), Url: "https://www.gstatic.com/generate_204", Interval: 300},
	}
}
