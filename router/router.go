package router

import (
	"github.com/gin-gonic/gin"
	"trojan-panel/api"
	"trojan-panel/middleware"
)

// Router 主路由
func Router(router *gin.Engine) {
	// 限流和日志
	router.Use(middleware.RateLimiterHandler(), middleware.LogHandler())
	initAuthRouter(router)
	// Self-service security routes require authentication, never a caller-supplied account ID.
	security := router.Group("/api/security", middleware.JWTHandler(), middleware.LoginRateLimit())
	security.GET("/status", api.SecurityStatus)
	security.GET("/diagnostics", api.SecurityDiagnostics)
	security.POST("/totp/setup", api.SetupTOTP)
	security.POST("/totp/confirm", api.ConfirmTOTP)
	security.POST("/totp/disable", api.DisableTOTP)
	security.POST("/subscription/rotate", api.RotateSubscription)
	security.POST("/nodes/rotate", api.RotateNodeCredentials)
	// 认证和权限
	router.Use(middleware.JWTHandler(), middleware.CasbinHandler())
	initApiRouter(router)
}
