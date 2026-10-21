package router

import (
	"github.com/gin-gonic/gin"
	"trojan-panel/api"
	"trojan-panel/middleware"
)

// 认证路由
func initAuthRouter(router *gin.Engine) {
	trojan := router.Group("/api")
	{
		trojanAuth := trojan.Group("/auth")
		{
			trojanAuth.GET("/health", func(c *gin.Context) { c.Status(204) })
			// 登录
			trojanAuth.POST("/login", middleware.LoginRateLimit(), api.Login)
			trojanAuth.GET("/entry/open", middleware.LoginRateLimit(), api.EntryOpen)
			trojanAuth.POST("/entry/open", middleware.LoginRateLimit(), api.EntryOpen)
			trojanAuth.GET("/entry/verify", api.EntryVerify)
			// 创建账户
			trojanAuth.POST("/register", api.Register)
			// 系统默认设置
			trojanAuth.GET("/setting", api.Setting)
			// 订阅
			trojanAuth.GET("/subscribe/:token", api.Subscribe)
			// 验证码
			trojanAuth.GET("/generateCaptcha", api.GenerateCaptcha)
		}
		trojanImage := trojan.Group("/image")
		{
			// logo
			trojanImage.GET("/logo", api.GetLogo)
		}
	}
}
