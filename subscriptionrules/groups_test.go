package subscriptionrules

import (
	"reflect"
	"testing"
)

func TestProxyGroupsOfferAutomaticAndManualSelection(t *testing.T) {
	groups := ProxyGroups([]string{"u1", "u2"})
	if len(groups) != 2 || groups[0].Name != "PROXY" || groups[0].Type != "select" || !reflect.DeepEqual(groups[0].Proxies, []string{"u1", "u2", "AUTO"}) {
		t.Fatalf("manual selection must retain nodes and offer AUTO: %+v", groups)
	}
	auto := groups[1]
	if auto.Name != "AUTO" || auto.Type != "url-test" || !reflect.DeepEqual(auto.Proxies, []string{"u1", "u2"}) || auto.Url != "https://www.gstatic.com/generate_204" || auto.Interval != 300 || auto.Tolerance != 0 {
		t.Fatalf("AUTO must test actual nodes every five minutes: %+v", auto)
	}
}

func TestProxyGroupsWithoutNodesReject(t *testing.T) {
	groups := ProxyGroups(nil)
	if len(groups) != 1 || !reflect.DeepEqual(groups[0].Proxies, []string{"REJECT"}) {
		t.Fatalf("empty subscriptions must not offer an empty AUTO group: %+v", groups)
	}
}

func TestProxyGroupsAvoidAutomaticNameCollision(t *testing.T) {
	groups := ProxyGroups([]string{"AUTO", "AUTO-2", "u1"})
	if groups[1].Name != "AUTO-3" || groups[0].Proxies[3] != "AUTO-3" {
		t.Fatalf("automatic group must not collide with a node name: %+v", groups)
	}
}
