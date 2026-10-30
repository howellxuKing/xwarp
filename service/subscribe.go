package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
	"trojan-panel/dao"
	"trojan-panel/model"
	"trojan-panel/model/bo"
	"trojan-panel/model/constant"
	"trojan-panel/model/vo"
	"trojan-panel/util"
)

// SubscribeClash
/**
Clash for windows 参考文档：
1. https://docs.cfw.lbyczf.com/contents/urlscheme.html
2. https://github.com/crossutility/Quantumult/blob/master/extra-subscription-feature.md
3. https://github.com/Dreamacro/clash/wiki/Configuration
*/
func SubscribeClash(pass string) (*model.Account, string, []byte, vo.SystemVo, error) {
	account, err := dao.SelectAccountClashSubscribe(pass)
	if err != nil {
		return nil, "", []byte{}, vo.SystemVo{}, err
	}
	nodes, err := dao.SelectNodes()
	if err != nil {
		return nil, "", []byte{}, vo.SystemVo{}, err
	}

	userInfo := fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d",
		*account.Upload,
		*account.Download,
		*account.Quota,
		*account.ExpireTime/1000)

	clashConfig := bo.ClashConfig{Mode: "rule"}
	var ClashConfigInterface []interface{}
	var proxies []string
	for _, item := range nodes {
		if *item.NodeTypeId == constant.Xray {
			nodeXray, err := dao.SelectNodeXrayById(item.NodeSubId)
			if err != nil {
				return nil, "", []byte{}, vo.SystemVo{}, err
			}

			streamSettings := bo.StreamSettings{}
			if nodeXray.StreamSettings != nil && *nodeXray.StreamSettings != "" {
				if err = json.Unmarshal([]byte(*nodeXray.StreamSettings), &streamSettings); err != nil {
					logrus.Errorln(fmt.Sprintf("SystemVo JSON反转失败 err: %v", err))
					return nil, "", []byte{}, vo.SystemVo{}, errors.New(constant.SysError)
				}
			}
			settings := bo.Settings{}
			if nodeXray.Settings != nil && *nodeXray.Settings != "" {
				if err = json.Unmarshal([]byte(*nodeXray.Settings), &settings); err != nil {
					logrus.Errorln(fmt.Sprintf("SystemVo JSON反转失败 err: %v", err))
					return nil, "", []byte{}, vo.SystemVo{}, errors.New(constant.SysError)
				}
			}
			switch *nodeXray.Protocol {
			case constant.ProtocolVless:
				vless := bo.Vless{
					Name:    *item.Name,
					Type:    constant.ClashVless,
					Server:  *item.Domain,
					Port:    *item.Port,
					Uuid:    util.GenerateUUID(pass),
					Network: streamSettings.Network,
					Tls:     true,
					Udp:     true,
					Flow:    *nodeXray.XrayFlow,
				}
				if streamSettings.Security == "tls" {
					vless.ClientFingerprint = streamSettings.TlsSettings.Fingerprint
					vless.SkipCertVerify = streamSettings.TlsSettings.AllowInsecure
					vless.ServerName = streamSettings.TlsSettings.ServerName
				} else if streamSettings.Security == "reality" {
					if len(streamSettings.RealitySettings.ServerNames) > 0 {
						vless.ServerName = streamSettings.RealitySettings.ServerNames[0]
					}
					if len(streamSettings.RealitySettings.ShortIds) > 0 {
						vless.RealityOpts.ShortId = streamSettings.RealitySettings.ShortIds[0]
					}
					vless.RealityOpts.PublicKey = *nodeXray.RealityPbk
					vless.ClientFingerprint = streamSettings.RealitySettings.Fingerprint
				} else if streamSettings.Security == "none" {
					vless.Tls = false
					vless.SkipCertVerify = false
					vless.ClientFingerprint = ""
				}
				if streamSettings.Network == "ws" {
					vless.WsOpts.Path = streamSettings.WsSettings.Path
					vless.WsOpts.Headers.Host = streamSettings.WsSettings.Headers.Host
				}
				ClashConfigInterface = append(ClashConfigInterface, vless)
				proxies = append(proxies, *item.Name)
			case constant.ProtocolVmess:
				vmess := bo.Vmess{
					Name:    *item.Name,
					Type:    constant.ClashVmess,
					Server:  *item.Domain,
					Port:    *item.Port,
					Uuid:    util.GenerateUUID(pass),
					AlterId: 0,
					Tls:     true,
					Udp:     true,
					Network: streamSettings.Network,
				}
				if settings.Encryption != "none" {
					vmess.Cipher = "auto"
				} else {
					vmess.Cipher = "none"
				}
				if streamSettings.Security == "tls" {
					vmess.ClientFingerprint = streamSettings.TlsSettings.Fingerprint
					vmess.SkipCertVerify = streamSettings.TlsSettings.AllowInsecure
					vmess.ServerName = streamSettings.TlsSettings.ServerName
				} else if streamSettings.Security == "none" {
					vmess.Tls = false
					vmess.SkipCertVerify = false
					vmess.ClientFingerprint = ""
				}
				if streamSettings.Network == "ws" {
					vmess.WsOpts.Path = streamSettings.WsSettings.Path
					vmess.WsOpts.Headers.Host = streamSettings.WsSettings.Headers.Host
				}
				ClashConfigInterface = append(ClashConfigInterface, vmess)
				proxies = append(proxies, *item.Name)
			case constant.ProtocolTrojan:
				trojan := bo.Trojan{
					Name:     *item.Name,
					Type:     constant.ClashTrojan,
					Server:   *item.Domain,
					Port:     *item.Port,
					Password: pass,
					Udp:      true,
				}
				if streamSettings.Security == "tls" {
					trojan.ClientFingerprint = streamSettings.TlsSettings.Fingerprint
					trojan.Sni = streamSettings.TlsSettings.ServerName
					trojan.Alpn = streamSettings.TlsSettings.Alpn
					trojan.SkipCertVerify = streamSettings.TlsSettings.AllowInsecure
				} else if streamSettings.Security == "none" {
					trojan.ClientFingerprint = ""
					trojan.SkipCertVerify = false
				}
				if streamSettings.Network == "ws" {
					trojan.WsOpts.Path = streamSettings.WsSettings.Path
					trojan.WsOpts.Headers.Host = streamSettings.WsSettings.Headers.Host
				}
				ClashConfigInterface = append(ClashConfigInterface, trojan)
				proxies = append(proxies, *item.Name)
			case constant.ProtocolShadowsocks:
				shadowsocks := bo.Shadowsocks{
					Name:     *item.Name,
					Type:     constant.ClashShadowsocks,
					Server:   *item.Domain,
					Port:     *item.Port,
					Cipher:   *nodeXray.XraySSMethod,
					Password: pass,
					Udp:      true,
				}
				ClashConfigInterface = append(ClashConfigInterface, shadowsocks)
				proxies = append(proxies, *item.Name)
			case constant.ProtocolSocks:
				socks := bo.Socks{
					Name:     *item.Name,
					Type:     constant.ClashSocks5,
					Server:   *item.Domain,
					Port:     *item.Port,
					Username: settings.Accounts[0].User,
					Password: settings.Accounts[0].Pass,
					Udp:      settings.Udp,
				}
				if streamSettings.Security == "tls" {
					socks.Tls = true
					socks.Fingerprint = streamSettings.TlsSettings.Fingerprint
					socks.SkipCertVerify = streamSettings.TlsSettings.AllowInsecure
				} else if streamSettings.Security == "none" {
					socks.SkipCertVerify = false
				}
				ClashConfigInterface = append(ClashConfigInterface, socks)
				proxies = append(proxies, *item.Name)
			}
		} else if *item.NodeTypeId == constant.TrojanGo {
			nodeTrojanGo, err := dao.SelectNodeTrojanGoById(item.NodeSubId)
			if err != nil {
				return nil, "", []byte{}, vo.SystemVo{}, err
			}
			trojanGo := bo.TrojanGo{
				Name:     *item.Name,
				Type:     constant.ClashTrojan,
				Server:   *item.Domain,
				Port:     *item.Port,
				Password: pass,
				Udp:      true,
				SNI:      *nodeTrojanGo.Sni,
			}
			if *nodeTrojanGo.WebsocketEnable == 1 {
				trojanGo.Network = "ws"
				trojanGo.WsOpts.Path = *nodeTrojanGo.WebsocketPath
				trojanGo.WsOpts.Headers.Host = *nodeTrojanGo.WebsocketHost
			}
			ClashConfigInterface = append(ClashConfigInterface, trojanGo)
			proxies = append(proxies, *item.Name)
		} else if *item.NodeTypeId == constant.Hysteria {
			nodeHysteria, err := dao.SelectNodeHysteriaById(item.NodeSubId)
			if err != nil {
				return nil, "", []byte{}, vo.SystemVo{}, err
			}
			hysteria := bo.Hysteria{
				Name:           *item.Name,
				Type:           constant.ClashSHysteria,
				Server:         *item.Domain,
				Port:           *item.Port,
				AuthStr:        pass,
				Obfs:           *nodeHysteria.Obfs,
				Protocol:       *nodeHysteria.Protocol,
				Up:             *nodeHysteria.UpMbps,
				Down:           *nodeHysteria.DownMbps,
				Sni:            *nodeHysteria.ServerName,
				SkipCertVerify: *nodeHysteria.Insecure == 1,
				FastOpen:       *nodeHysteria.FastOpen == 1,
			}
			ClashConfigInterface = append(ClashConfigInterface, hysteria)
			proxies = append(proxies, *item.Name)
		} else if *item.NodeTypeId == constant.Hysteria2 {
			nodeHysteria2, err := dao.SelectNodeHysteria2ById(item.NodeSubId)
			if err != nil {
				return nil, "", []byte{}, vo.SystemVo{}, err
			}
			hysteria2 := bo.Hysteria2{
				Name:           *item.Name,
				Type:           constant.ClashSHysteria2,
				Server:         *item.Domain,
				Port:           *item.Port,
				Password:       pass,
				Up:             *nodeHysteria2.UpMbps,
				Down:           *nodeHysteria2.DownMbps,
				SkipCertVerify: *nodeHysteria2.Insecure == 1,
			}
			if nodeHysteria2.ObfsPassword != nil && *nodeHysteria2.ObfsPassword != "" {
				hysteria2.Obfs = "salamander"
				hysteria2.ObfsPassword = *nodeHysteria2.ObfsPassword
			}
			if nodeHysteria2.ServerName != nil && *nodeHysteria2.ServerName != "" {
				hysteria2.Sni = *nodeHysteria2.ServerName
			}
			ClashConfigInterface = append(ClashConfigInterface, hysteria2)
			proxies = append(proxies, *item.Name)
		}
	}
	proxyGroups := make([]bo.ProxyGroup, 0, 3)
	if len(proxies) == 0 {
		// 没有节点时仍生成可加载的配置，避免客户端整份订阅报错
		proxyGroups = append(proxyGroups, bo.ProxyGroup{Name: "PROXY", Type: "select", Proxies: []string{"DIRECT"}})
	} else {
		proxyGroups = append(proxyGroups,
			// 默认选自动测速，用户不需要手动挑节点
			bo.ProxyGroup{Name: "PROXY", Type: "select", Proxies: append([]string{"AUTO", "FALLBACK", "DIRECT"}, proxies...)},
			bo.ProxyGroup{Name: "AUTO", Type: "url-test", Proxies: proxies, Url: "https://www.gstatic.com/generate_204", Interval: 300, Tolerance: 50},
			bo.ProxyGroup{Name: "FALLBACK", Type: "fallback", Proxies: proxies, Url: "https://www.gstatic.com/generate_204", Interval: 300},
		)
	}
	clashConfig.ProxyGroups = proxyGroups
	clashConfig.Proxies = ClashConfigInterface

	clashConfigYaml, err := yaml.Marshal(&clashConfig)
	if err != nil {
		return nil, "", []byte{}, vo.SystemVo{}, errors.New(constant.SysError)
	}

	systemName := constant.SystemName
	systemConfig, err := SelectSystemByName(&systemName)
	if err != nil {
		return nil, "", []byte{}, vo.SystemVo{}, errors.New(constant.SysError)
	}
	return account, userInfo, clashConfigYaml, systemConfig, nil
}
