package service

import (
	"encoding/json"
	"errors"
	"fmt"
	redisgo "github.com/gomodule/redigo/redis"
	"github.com/sirupsen/logrus"
	"os"
	"strings"
	"time"
	"trojan-panel/dao"
	"trojan-panel/dao/redis"
	"trojan-panel/model"
	"trojan-panel/model/bo"
	"trojan-panel/model/constant"
	"trojan-panel/model/dto"
	"trojan-panel/model/vo"
	"trojan-panel/subscriptionrules"
)

func SelectSystemByName(name *string) (vo.SystemVo, error) {
	var systemVo vo.SystemVo
	bytes, err := redis.Client.String.Get("trojan-panel:system").Bytes()
	if err != nil && err != redisgo.ErrNil {
		return systemVo, errors.New(constant.SysError)
	}
	if len(bytes) > 0 {
		if err = json.Unmarshal(bytes, &systemVo); err != nil {
			logrus.Errorln(fmt.Sprintf("SelectSystemByName SystemVo deserialization err: %v", err))
			return systemVo, errors.New(constant.SysError)
		}
		return systemVo, nil
	} else {
		system, err := dao.SelectSystemByName(name)
		if err != nil {
			return systemVo, err
		}

		systemAccountConfigBo := bo.SystemAccountConfigBo{}
		if err = json.Unmarshal([]byte(*system.AccountConfig), &systemAccountConfigBo); err != nil {
			logrus.Errorln(fmt.Sprintf("SelectSystemByName SystemAccountConfigBo deserialization err: %v", err))
			return systemVo, errors.New(constant.SysError)
		}
		systemEmailConfigBo := bo.SystemEmailConfigBo{}
		if err = json.Unmarshal([]byte(*system.EmailConfig), &systemEmailConfigBo); err != nil {
			logrus.Errorln(fmt.Sprintf("SelectSystemByName SystemEmailConfigBo deserialization err: %v", err))
			return systemVo, errors.New(constant.SysError)
		}
		systemTemplateConfigBo := bo.SystemTemplateConfigBo{}
		if err = json.Unmarshal([]byte(*system.TemplateConfig), &systemTemplateConfigBo); err != nil {
			logrus.Errorln(fmt.Sprintf("SelectSystemByName SystemTemplateConfigBo deserialization err: %v", err))
			return systemVo, errors.New(constant.SysError)
		}
		// 读取Clash规则默认模板文件
		clashRuleContent, err := os.ReadFile(constant.ClashRuleFilePath)
		if err != nil {
			logrus.Errorln(fmt.Sprintf("failed to read default template of Clash rule err: %v", err))
			return systemVo, errors.New(constant.SysError)
		}
		// 读取Xray默认模板文件
		xrayTemplateContent, err := os.ReadFile(constant.XrayTemplateFilePath)
		if err != nil {
			logrus.Errorln(fmt.Sprintf("failed to read Xray default template file err: %v", err))
			return systemVo, errors.New(constant.SysError)
		}

		systemVo = vo.SystemVo{
			Id:                          *system.Id,
			RegisterEnable:              systemAccountConfigBo.RegisterEnable,
			RegisterQuota:               systemAccountConfigBo.RegisterQuota,
			RegisterExpireDays:          systemAccountConfigBo.RegisterExpireDays,
			ResetDownloadAndUploadMonth: systemAccountConfigBo.ResetDownloadAndUploadMonth,
			TrafficRankEnable:           systemAccountConfigBo.TrafficRankEnable,
			CaptchaEnable:               systemAccountConfigBo.CaptchaEnable,
			ExpireWarnEnable:            systemEmailConfigBo.ExpireWarnEnable,
			ExpireWarnDay:               systemEmailConfigBo.ExpireWarnDay,
			EmailEnable:                 systemEmailConfigBo.EmailEnable,
			EmailHost:                   systemEmailConfigBo.EmailHost,
			EmailPort:                   systemEmailConfigBo.EmailPort,
			EmailUsername:               systemEmailConfigBo.EmailUsername,
			EmailPassword:               systemEmailConfigBo.EmailPassword,
			SystemName:                  systemTemplateConfigBo.SystemName,
			ClashRule:                   string(clashRuleContent),
			XrayTemplate:                string(xrayTemplateContent),
			ClashDirectDomains:          systemTemplateConfigBo.ClashDirectDomains,
			ClashProxyDomains:           systemTemplateConfigBo.ClashProxyDomains,
		}

		systemVoJson, err := json.Marshal(systemVo)
		if err != nil {
			logrus.Errorln(fmt.Sprintf("SelectSystemByName SystemVo serialization err: %v", err))
			return systemVo, errors.New(constant.SysError)
		}
		redis.Client.String.Set("trojan-panel:system", systemVoJson, time.Minute.Milliseconds()*30/1000)

		return systemVo, nil
	}
}

func UpdateSystemById(systemDto dto.SystemUpdateDto) error {
	accountConfigBo := bo.SystemAccountConfigBo{}
	if systemDto.RegisterEnable != nil {
		accountConfigBo.RegisterEnable = *systemDto.RegisterEnable
	}
	if systemDto.RegisterQuota != nil {
		accountConfigBo.RegisterQuota = *systemDto.RegisterQuota
	}
	if systemDto.RegisterExpireDays != nil {
		accountConfigBo.RegisterExpireDays = *systemDto.RegisterExpireDays
	}
	if systemDto.ResetDownloadAndUploadMonth != nil {
		accountConfigBo.ResetDownloadAndUploadMonth = *systemDto.ResetDownloadAndUploadMonth
	}
	if systemDto.TrafficRankEnable != nil {
		accountConfigBo.TrafficRankEnable = *systemDto.TrafficRankEnable
	}
	if systemDto.CaptchaEnable != nil {
		accountConfigBo.CaptchaEnable = *systemDto.CaptchaEnable
	}
	accountConfigBoByte, err := json.Marshal(accountConfigBo)
	if err != nil {
		logrus.Errorln(fmt.Sprintf("UpdateSystemById SystemAccountConfigBo serialization err: %v", err))
	}
	accountConfigBoJsonStr := string(accountConfigBoByte)

	systemEmailConfigBo := bo.SystemEmailConfigBo{}
	if systemDto.ExpireWarnEnable != nil {
		systemEmailConfigBo.ExpireWarnEnable = *systemDto.ExpireWarnEnable
	}
	if systemDto.ExpireWarnDay != nil {
		systemEmailConfigBo.ExpireWarnDay = *systemDto.ExpireWarnDay
	}
	if systemDto.EmailEnable != nil {
		systemEmailConfigBo.EmailEnable = *systemDto.EmailEnable
	}
	if systemDto.EmailHost != nil {
		systemEmailConfigBo.EmailHost = *systemDto.EmailHost
	}
	if systemDto.EmailPort != nil {
		systemEmailConfigBo.EmailPort = *systemDto.EmailPort
	}
	if systemDto.EmailUsername != nil {
		systemEmailConfigBo.EmailUsername = *systemDto.EmailUsername
	}
	if systemDto.EmailPassword != nil {
		systemEmailConfigBo.EmailPassword = *systemDto.EmailPassword
	}
	systemEmailConfigBoByte, err := json.Marshal(systemEmailConfigBo)
	if err != nil {
		logrus.Errorln(fmt.Sprintf("UpdateSystemById SystemEmailConfigBo serialization err: %v", err))
	}
	systemEmailConfigBoStr := string(systemEmailConfigBoByte)

	systemTemplateConfigBo := bo.SystemTemplateConfigBo{}
	// 先读取现有模板配置，避免本次未提交的字段被清空
	systemName := constant.SystemName
	if system, dbErr := dao.SelectSystemByName(&systemName); dbErr == nil && system.TemplateConfig != nil {
		if err = json.Unmarshal([]byte(*system.TemplateConfig), &systemTemplateConfigBo); err != nil {
			logrus.Errorln(fmt.Sprintf("UpdateSystemById SystemTemplateConfigBo deserialization err: %v", err))
		}
	}
	if systemDto.SystemName != nil {
		systemTemplateConfigBo.SystemName = *systemDto.SystemName
	}
	// 订阅自定义直连/代理网站（一行一个域名，留空表示不添加）
	if systemDto.ClashDirectDomains != nil {
		systemTemplateConfigBo.ClashDirectDomains = *systemDto.ClashDirectDomains
	}
	if systemDto.ClashProxyDomains != nil {
		systemTemplateConfigBo.ClashProxyDomains = *systemDto.ClashProxyDomains
	}
	// 先校验 Clash 规则模板，校验失败时不产生任何副作用
	var clashRule string
	if systemDto.ClashRule != nil {
		clashRule = *systemDto.ClashRule
		// 空内容表示恢复内置默认模板
		if strings.TrimSpace(clashRule) == "" {
			clashRule = constant.ClashRules
		}
		// 模板必须保留占位行，否则保存后大陆域名不再自动直连
		if !strings.Contains(clashRule, constant.ClashDomesticMarker) {
			return fmt.Errorf("Clash 规则模板缺少占位行 %s：请保留该行，否则保存后大陆域名将不再自动直连", constant.ClashDomesticMarker)
		}
		if err := subscriptionrules.Validate(clashRule); err != nil {
			return fmt.Errorf("Clash 规则模板不合法: %w", err)
		}
		// 兜底直连或 GEOIP,cn 解析域名的模板会让规则模式把国外站点送去直连
		if err := subscriptionrules.ValidatePolicy(clashRule); err != nil {
			return fmt.Errorf("Clash 规则模板会让规则模式把国外站点送去直连: %w", err)
		}
	}
	// 根据自定义名单重新生成订阅规则文件（插入在内置规则之前）
	if err = writeClashCustomRuleFile(systemTemplateConfigBo.ClashProxyDomains, systemTemplateConfigBo.ClashDirectDomains); err != nil {
		logrus.Errorln(fmt.Sprintf("UpdateSystemById write clash custom rule file err: %v", err))
	}
	if systemDto.ClashRule != nil {
		// 修改Clash规则默认模板文件
		if err := os.WriteFile(constant.ClashRuleFilePath, []byte(clashRule), 0600); err != nil {
			logrus.Errorf("write Clash rule default template file err: %v", err)
			return fmt.Errorf("写入 Clash 规则模板失败: %w", err)
		}
	}
	if systemDto.XrayTemplate != nil {
		// 修改Xray默认模板文件
		xrayConfigBo := bo.XrayConfigBo{}
		// 将json字符串映射到模板对象
		if err = json.Unmarshal([]byte(*systemDto.XrayTemplate), &xrayConfigBo); err != nil {
			logrus.Errorf("systemDto XrayTemplate deserialization err: %v", err)
			return err
		}
		xrayConfigBoStr, err := json.MarshalIndent(xrayConfigBo, "", "    ")
		if err != nil {
			logrus.Errorf("xrayConfigBo serialization err: %v", err)
			return err
		}
		if err := os.WriteFile(constant.XrayTemplateFilePath, xrayConfigBoStr, 0666); err != nil {
			logrus.Errorln(fmt.Sprintf("write Xray default template file err: %v", err))
		}
	}
	systemTemplateConfigBoByte, err := json.Marshal(systemTemplateConfigBo)
	if err != nil {
		logrus.Errorln(fmt.Sprintf("UpdateSystemById SystemTemplateConfigBo serialization err: %v", err))
	}
	systemTemplateConfigBoStr := string(systemTemplateConfigBoByte)

	system := model.System{
		Id:             systemDto.Id,
		AccountConfig:  &accountConfigBoJsonStr,
		EmailConfig:    &systemEmailConfigBoStr,
		TemplateConfig: &systemTemplateConfigBoStr,
	}

	if err := dao.UpdateSystemById(&system); err != nil {
		return err
	}
	_ = redis.Client.Key.RetryDel("trojan-panel:system")
	return nil
}

// writeClashCustomRuleFile 根据面板配置的自定义代理/直连网站生成订阅自定义规则文件
// 顺序：先代理、后直连（代理优先，避免把需要代理的站点误判为直连）；订阅时插入到内置规则之前
func writeClashCustomRuleFile(proxyDomains string, directDomains string) error {
	var lines []string
	appendRules := func(text string, policy string) {
		for _, raw := range strings.FieldsFunc(text, func(r rune) bool {
			return r == 10 || r == 13 || r == ',' || r == ';' || r == 9
		}) {
			if domain := normalizeClashDomain(raw); domain != "" {
				lines = append(lines, fmt.Sprintf("  - DOMAIN-SUFFIX,%s,%s", domain, policy))
			}
		}
	}
	appendRules(proxyDomains, "PROXY")
	appendRules(directDomains, "DIRECT")

	content := ""
	if len(lines) > 0 {
		content = strings.Join(lines, "\n") + "\n"
	}
	return os.WriteFile(constant.ClashCustomRuleFilePath, []byte(content), 0666)
}

// normalizeClashDomain 清洗用户输入的网站/域名（去协议、路径、端口、通配符、www.）
func normalizeClashDomain(raw string) string {
	s := strings.TrimSpace(strings.ToLower(raw))
	if s == "" || strings.HasPrefix(s, "#") {
		return ""
	}
	for _, prefix := range []string{"http://", "https://", "socks5://", "socks://"} {
		s = strings.TrimPrefix(s, prefix)
	}
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	if i := strings.Index(s, ":"); i >= 0 {
		s = s[:i]
	}
	s = strings.TrimPrefix(s, "*.")
	s = strings.TrimPrefix(s, ".")
	s = strings.TrimPrefix(s, "www.")
	if !strings.Contains(s, ".") || strings.Contains(s, " ") {
		return ""
	}
	return s
}
