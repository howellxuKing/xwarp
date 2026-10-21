package main

import (
	"fmt"
	"github.com/gin-gonic/gin"
	"os"
	"path/filepath"
	"strings"
	"trojan-panel/api"
	"trojan-panel/core"
	"trojan-panel/dao"
	"trojan-panel/dao/redis"
	"trojan-panel/middleware"
	"trojan-panel/model/constant"
	"trojan-panel/router"
	"trojan-panel/security"
)

func main() {
	serverConfig := core.Config.ServerConfig
	r := gin.New()
	r.Use(middleware.SafeRecovery())
	proxies := strings.Split(os.Getenv("XWARP_TRUSTED_PROXIES"), ",")
	if os.Getenv("XWARP_TRUSTED_PROXIES") == "" {
		proxies = []string{"127.0.0.1", "::1"}
	}
	if err := r.SetTrustedProxies(proxies); err != nil {
		panic(err)
	}
	router.Router(r)
	bind := os.Getenv("XWARP_API_BIND")
	if bind == "" {
		bind = "127.0.0.1"
	}
	if err := r.Run(fmt.Sprintf("%s:%d", bind, serverConfig.Port)); err != nil {
		panic(err)
	}
	defer releaseResource()
}

func init() {
	core.InitConfig()
	middleware.InitLog()
	dao.InitMySQL()
	if err := dao.InitSecurity(); err != nil {
		panic(err)
	}
	redis.InitRedis()
	if core.ResetAdminPassword {
		plain, err := security.RandomPassword(16)
		if err != nil {
			panic(err)
		}
		path := filepath.Join(constant.ConfigPath, "recovered-admin-"+security.Digest(plain)[:12]+".txt")
		f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err != nil {
			panic(err)
		}
		_, writeErr := f.WriteString(plain + "\n")
		closeErr := f.Close()
		if writeErr != nil || closeErr != nil {
			os.Remove(path)
			panic("cannot persist recovered password")
		}
		username, resetErr := dao.ResetAdministrator(plain)
		if resetErr != nil {
			os.Remove(path)
			panic(resetErr)
		}
		if err := redis.Client.Key.RetryDel("trojan-panel:token:" + username); err != nil {
			panic(err)
		}
		fmt.Printf("Administrator login recovered. Read %s locally; remove after changing the password.\n", path)
		os.Exit(0)
	}
	middleware.InitCron()
	middleware.InitRateLimiter()
	api.InitValidator()
}

func releaseResource() {
	dao.CloseDb()
	redis.CloseRedis()
}
