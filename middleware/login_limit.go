package middleware

import (
	"github.com/gin-gonic/gin"
	"time"
	"trojan-panel/security"
)

var loginLimiter = security.NewLimiter()

func LoginRateLimit() gin.HandlerFunc {
	return func(c *gin.Context) {
		if !loginLimiter.Allow(c.ClientIP(), 20, time.Minute, time.Now()) {
			c.Header("Retry-After", "60")
			c.AbortWithStatusJSON(429, gin.H{"code": 50000, "message": "请求过于频繁，请稍后重试"})
			return
		}
		c.Next()
	}
}
