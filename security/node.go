package security

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var panelPathPattern = regexp.MustCompile(`^/(?:[A-Za-z0-9_-]+/)*$`)

func ValidPanelPath(path string) bool { return len(path) <= 128 && panelPathPattern.MatchString(path) }

func ValidateXray(protocol, flow, publicKey, encoded string) error {
	if encoded == "" {
		return nil
	}
	var config struct {
		Network  string `json:"network"`
		Security string `json:"security"`
		Reality  struct {
			Dest        string   `json:"dest"`
			Target      string   `json:"target"`
			PrivateKey  string   `json:"privateKey"`
			ServerNames []string `json:"serverNames"`
			ShortIDs    []string `json:"shortIds"`
		} `json:"realitySettings"`
	}
	if json.Unmarshal([]byte(encoded), &config) != nil {
		return errors.New("传输配置不是有效JSON")
	}
	if config.Security != "reality" {
		return nil
	}
	if protocol != "vless" || config.Network != "tcp" {
		return errors.New("当前面板REALITY模板只支持VLESS TCP")
	}
	if flow != "" && flow != "none" && flow != "xtls-rprx-vision" {
		return errors.New("REALITY流控不受支持")
	}
	for _, key := range []string{publicKey, config.Reality.PrivateKey} {
		decoded, err := base64.RawURLEncoding.DecodeString(key)
		if err != nil || len(decoded) != 32 {
			return errors.New("REALITY公钥和私钥须为32字节的URL安全Base64")
		}
	}
	target := config.Reality.Target
	if target == "" {
		target = config.Reality.Dest
	}
	host, portText, targetErr := net.SplitHostPort(target)
	targetPort, portErr := strconv.Atoi(portText)
	if targetErr != nil || portErr != nil || targetPort < 1 || targetPort > 65535 || host == "" || strings.ContainsAny(host, "/ \t\r\n") {
		return errors.New("REALITY目标须使用主机:端口格式")
	}
	if len(config.Reality.ServerNames) == 0 || len(config.Reality.ShortIDs) == 0 {
		return errors.New("REALITY需要serverNames和shortIds")
	}
	for _, name := range config.Reality.ServerNames {
		if strings.TrimSpace(name) != name || name == "" || strings.ContainsAny(name, "/*: ") {
			return errors.New("serverNames须为不含协议、端口的域名")
		}
	}
	for _, id := range config.Reality.ShortIDs {
		if len(id) > 16 || len(id)%2 != 0 {
			return errors.New("shortIds须为偶数长度、最多16位十六进制")
		}
		if _, err := hex.DecodeString(id); err != nil {
			return errors.New("shortIds包含非十六进制字符，请移除空格或HTML转义字符")
		}
	}
	return nil
}
