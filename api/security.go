package api

import (
	"encoding/json"
	"github.com/gin-gonic/gin"
	"net/url"
	"os"
	"strings"
	"trojan-panel/dao"
	"trojan-panel/model/vo"
	"trojan-panel/security"
	"trojan-panel/service"
	"trojan-panel/util"
)

type securityAction struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

func verifySecurityAction(c *gin.Context) (uint, securityAction, bool) {
	account := service.GetCurrentAccount(c)
	var action securityAction
	if c.ShouldBindJSON(&action) != nil || len(action.Password) > 72 || len(action.Code) > 32 {
		vo.Fail("请求格式错误", c)
		return 0, action, false
	}
	username, nodePassword, err := dao.SecurityAccount(account.Id)
	if err != nil || dao.Security.CheckPassword(account.Id, username, nodePassword, action.Password) != nil || dao.Security.CheckMFA(account.Id, action.Code) != nil {
		vo.Fail("密码或动态验证码错误", c)
		return 0, action, false
	}
	return account.Id, action, true
}

func SecurityStatus(c *gin.Context) {
	account := service.GetCurrentAccount(c)
	r, err := dao.Security.Read(account.Id)
	if err != nil {
		vo.Fail("读取安全设置失败", c)
		return
	}
	var codes []string
	_ = json.Unmarshal([]byte(r.Recovery), &codes)
	vo.Success(gin.H{"totpEnabled": r.TOTPCipher != "", "recoveryCodesRemaining": len(codes), "legacySubscriptionAllowed": r.LegacyAllowed, "subscriptionBase": security.RuntimeGateway().SubscriptionBase}, c)
}

func SecurityDiagnostics(c *gin.Context) {
	account := service.GetCurrentAccount(c)
	if account.RoleId != 1 {
		c.AbortWithStatus(403)
		return
	}
	data, err := os.ReadFile("logs/security-health.json")
	if err != nil {
		vo.Success(gin.H{"available": false, "message": "尚未配置服务器健康检查；安装监控定时器后显示结果"}, c)
		return
	}
	var result interface{}
	if json.Unmarshal(data, &result) != nil {
		vo.Fail("健康检查记录损坏", c)
		return
	}
	c.Header("Cache-Control", "no-store")
	vo.Success(gin.H{"available": true, "report": result}, c)
}

func SetupTOTP(c *gin.Context) {
	id, _, ok := verifySecurityAction(c)
	if !ok {
		return
	}
	username, _, err := dao.SecurityAccount(id)
	if err != nil {
		vo.Fail("读取账号失败", c)
		return
	}
	secret, uri, err := dao.Security.BeginTOTP(id, username)
	if err != nil {
		vo.Fail(err.Error(), c)
		return
	}
	c.Header("Cache-Control", "no-store")
	vo.Success(gin.H{"secret": secret, "uri": uri}, c)
}

func ConfirmTOTP(c *gin.Context) {
	id, action, ok := verifySecurityAction(c)
	if !ok {
		return
	}
	codes, err := dao.Security.ConfirmTOTP(id, action.Code)
	if err != nil {
		vo.Fail("验证码错误或绑定请求已过期", c)
		return
	}
	c.Header("Cache-Control", "no-store")
	vo.Success(gin.H{"recoveryCodes": codes}, c)
}

func DisableTOTP(c *gin.Context) {
	id, _, ok := verifySecurityAction(c)
	if !ok {
		return
	}
	if dao.Security.DisableTOTP(id) != nil {
		vo.Fail("关闭失败", c)
		return
	}
	vo.Success(nil, c)
}

func RotateSubscription(c *gin.Context) {
	id, _, ok := verifySecurityAction(c)
	if !ok {
		return
	}
	token, err := dao.Security.Subscription(id, true)
	if err != nil {
		vo.Fail("更换订阅失败", c)
		return
	}
	c.Header("Cache-Control", "no-store")
	vo.Success(SubscriptionURL(token), c)
}

func SubscriptionURL(token string) string {
	base := strings.TrimRight(security.RuntimeGateway().SubscriptionBase, "/")
	if base != "" {
		u, err := url.Parse(base)
		if err != nil || u.Scheme != "https" || u.Host == "" {
			return "/api/auth/subscribe/" + token
		}
	}
	return base + "/api/auth/subscribe/" + token
}

func RotateNodeCredentials(c *gin.Context) {
	id, _, ok := verifySecurityAction(c)
	if !ok {
		return
	}
	old, err := dao.Security.RotateNodeCredentials(id)
	if err != nil {
		vo.Fail("更换节点凭据失败", c)
		return
	}
	// The old core's removal API is best-effort. Never promise existing sessions were revoked.
	_ = service.RemoveAccount(util.GetToken(c), old)
	c.Header("Cache-Control", "no-store")
	vo.Success(gin.H{"restartRequired": true, "message": "数据库中的节点凭据已更换，旧版订阅链接已失效。请刷新订阅，并由管理员重启相关节点以清除已有连接和核心缓存。登录密码、新订阅令牌保持不变。"}, c)
}
