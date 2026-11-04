package api

import (
	"encoding/base64"
	"fmt"
	"os"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"trojan-panel/dao"
	"trojan-panel/model/constant"
	"trojan-panel/model/dto"
	"trojan-panel/model/vo"
	"trojan-panel/service"
	"trojan-panel/subscriptionrules"
)

// ClashSubscribe 获取Clash订阅地址
func ClashSubscribe(c *gin.Context) {
	accountVo := service.GetCurrentAccount(c)
	token, err := dao.Security.Subscription(accountVo.Id, false)
	if err != nil {
		vo.Fail("读取订阅失败", c)
		return
	}
	c.Header("Cache-Control", "no-store")
	vo.Success(SubscriptionURL(token), c)
}

// ClashSubscribeForSb 获取指定人的Clash订阅地址
func ClashSubscribeForSb(c *gin.Context) {
	var accountRequiredIdDto dto.RequiredIdDto
	_ = c.ShouldBindQuery(&accountRequiredIdDto)
	if err := validate.Struct(&accountRequiredIdDto); err != nil {
		vo.Fail(constant.ValidateFailed, c)
		return
	}
	token, err := dao.Security.Subscription(*accountRequiredIdDto.Id, false)
	if err != nil {
		vo.Fail("读取订阅失败", c)
		return
	}
	c.Header("Cache-Control", "no-store")
	vo.Success(SubscriptionURL(token), c)
}

// Subscribe 订阅
func Subscribe(c *gin.Context) {
	token := c.Param("token")
	_, pass, err := dao.Security.ResolveSubscription(token)
	if err != nil {
		decoded, decodeErr := base64.StdEncoding.DecodeString(token)
		if decodeErr != nil || !dao.Security.LegacySubscriptionAllowed(string(decoded)) {
			c.AbortWithStatus(404)
			return
		}
		pass = string(decoded)
	}
	c.Header("Cache-Control", "no-store")
	//if strings.HasPrefix(userAgent, constant.ClashforWindows) {
	account, userInfo, clashConfigYaml, _, err := service.SubscribeClash(pass)
	if err != nil {
		vo.Fail(err.Error(), c)
		return
	}
	rules, err := getClashRules()
	if err != nil {
		vo.Fail("订阅规则格式错误，请联系管理员检查模板设置", c)
		return
	}
	result := fmt.Sprintf("%s\n%s", string(clashConfigYaml), rules)

	c.Header("content-disposition", fmt.Sprintf("attachment; filename=%s.yaml", *account.Username))
	c.Header("profile-update-interval", "12")
	c.Header("subscription-userinfo", userInfo)
	c.String(200, result)
	return
	//}
	//vo.Fail("This client is not supported", c)
}

// Local destinations first, then administrator exceptions and the visible template.
func getClashRules() (string, error) {
	return subscriptionrules.Compose(getBaseClashRules(), getCustomClashRules(), constant.ClashLocalRules)
}

// getCustomClashRules 面板「模板设置」中自定义的直连/代理网站生成的规则
// 由面板保存时生成：config/template/clash-custom-rule.yaml；文件不存在或为空表示未配置自定义网站
func getCustomClashRules() string {
	content, err := os.ReadFile(constant.ClashCustomRuleFilePath)
	if err != nil {
		return ""
	}
	return string(content)
}

// getBaseClashRules 返回基础订阅规则
// 优先读取面板可编辑的规则模板文件（config/template/template-clash-rule.yaml，系统设置→Clash规则 保存后即写入）；
// 文件缺失、为空或匹配已知旧版默认内容时，采用当前内置规则。
// 管理员修改过的模板会保留，但同样会展开大陆域名占位行。
func getBaseClashRules() string {
	content, err := os.ReadFile(constant.ClashRuleFilePath)
	if err != nil {
		return service.DefaultClashRules()
	}
	rules := strings.TrimSpace(string(content))
	normalizedRules := strings.ReplaceAll(rules, "\r\n", "\n")
	rulesDigest := subscriptionrules.CanonicalDigest(string(content))
	if rules == "" || isBuiltinClashRules(rulesDigest, normalizedRules) {
		return service.DefaultClashRules()
	}
	// 自定义模板也要展开大陆域名块，否则国内网站会退化为按 IP 判定
	applied := rules
	if strings.Contains(rules, constant.ClashDomesticMarker) {
		var applyErr error
		applied, applyErr = service.ApplyDomesticRules(rules)
		if applyErr != nil { return service.DefaultClashRules() }
	}
	// 模板把未匹配流量兜底成直连、或让 GEOIP,cn 解析域名时，规则模式会把国外站点送去直连。
	// 这类模板直接作废，回落到内置默认规则，避免客户端拿到一份「全局能用、规则不能用」的配置。
	if policyErr := subscriptionrules.ValidatePolicy(applied); policyErr != nil {
		logrus.Warnf("自定义 Clash 规则模板不满足分流模型，本次订阅改用内置默认规则: %v", policyErr)
		return service.DefaultClashRules()
	}
	return applied
}

// isBuiltinClashRules 判断模板是否为历史版本的内置默认内容（可安全替换为当前默认）。
func isBuiltinClashRules(digest, normalized string) bool {
	switch digest {
	case constant.ClashRulesV233SHA256, constant.ClashRulesPreviousSHA256, constant.ClashRulesV250SHA256, constant.ClashRulesV251SHA256, constant.ClashRulesV252SHA256, constant.ClashRulesV254SHA256, constant.ClashRulesV255SHA256, constant.ClashRulesV3SHA256:
		return true
	}
	return normalized == strings.TrimSpace(constant.ClashRules) ||
		normalized == "rules:\n  - GEOIP,CN,DIRECT\n  - MATCH,PROXY"
}
