package service

import (
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/sirupsen/logrus"
	"time"
	"trojan-panel/dao"
	"trojan-panel/dao/redis"
	"trojan-panel/model/constant"
	"trojan-panel/model/vo"
	"trojan-panel/util"
)

// CronTrafficRank 流量排行榜 一小时更新一次
func CronTrafficRank() {
	_, _ = TrafficRank()
}

func TrafficRank() ([]vo.AccountTrafficRankVo, error) {
	roleIds := []uint{constant.USER}
	trafficRank, err := dao.TrafficRank(roleIds)
	for index, item := range trafficRank {
		trafficRank[index].Username = util.MaskTrafficRankName(item.Username)
	}
	if err != nil {
		return nil, err
	}
	trafficRankJson, err := json.Marshal(trafficRank)
	if err != nil {
		logrus.Errorln(fmt.Sprintf("AccountTrafficRankVo serialization err: %v", err))
		return nil, errors.New(constant.SysError)
	}
	redis.Client.String.Set("trojan-panel:trafficRank", trafficRankJson, time.Hour.Milliseconds()*2/1000)
	return trafficRank, nil
}

func PanelGroup(c *gin.Context) (*vo.PanelGroupVo, error) {
	accountInfo, err := GetAccountInfo(c)
	if err != nil {
		return nil, err
	}
	account, err := SelectAccountById(&accountInfo.Id)
	if err != nil {
		return nil, err
	}
	nodeCount, err := CountNode()
	if err != nil {
		return nil, err
	}
	panelGroupVo := vo.PanelGroupVo{
		Quota:        *account.Quota,
		ResidualFlow: *account.Quota - *account.Upload - *account.Download,
		NodeCount:    nodeCount,
		ExpireTime:   *account.ExpireTime,
	}
	if util.IsAdmin(accountInfo.Roles) {
		var err error
		accountCount, err := CountAccountByUsername(nil)
		cpuUsed, err := util.GetCpuPercent()
		memUsed, err := util.GetMemPercent()
		diskUsed, err := util.GetDiskPercent()
		if err != nil {
			return nil, err
		}
		panelGroupVo.AccountCount = accountCount
		panelGroupVo.CpuUsed = cpuUsed
		panelGroupVo.MemUsed = memUsed
		panelGroupVo.DiskUsed = diskUsed
	}
	return &panelGroupVo, nil
}
