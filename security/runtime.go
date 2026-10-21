package security

import (
	"encoding/json"
	"os"
)

type GatewayConfig struct {
	PanelPath        string `json:"panel_path"`
	SubscriptionBase string `json:"subscription_base"`
}

func RuntimeGateway() GatewayConfig {
	r := GatewayConfig{PanelPath: "/"}
	if data, err := os.ReadFile("config/gateway.json"); err == nil {
		_ = json.Unmarshal(data, &r)
	}
	if v := os.Getenv("XWARP_PANEL_PATH"); v != "" {
		r.PanelPath = v
	}
	if v := os.Getenv("XWARP_SUBSCRIPTION_BASE_URL"); v != "" {
		r.SubscriptionBase = v
	}
	return r
}
