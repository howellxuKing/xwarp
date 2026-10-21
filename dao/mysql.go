package dao

import (
	"database/sql"
	"github.com/didi/gendry/manager"
	_ "github.com/go-sql-driver/mysql"
	"github.com/sirupsen/logrus"
	"net/url"
	"path/filepath"
	"strings"
	"time"
	"trojan-panel/core"
	"trojan-panel/model/constant"
	"trojan-panel/security"
)

var db *sql.DB

// InitMySQL 初始化数据库
func InitMySQL() {
	mySQLConfig := core.Config.MySQLConfig
	var err error

	db, err = manager.
		New("trojan_panel_db", mySQLConfig.User, mySQLConfig.Password, mySQLConfig.Host).
		Set(
			manager.SetCharset("utf8mb4"),
			manager.SetAllowCleartextPasswords(true),
			manager.SetInterpolateParams(true),
			manager.SetTimeout(1*time.Second),
			manager.SetReadTimeout(1*time.Second),
			manager.SetLoc(url.QueryEscape("Asia/Shanghai"))).
		Port(mySQLConfig.Port).Open(true)

	if err != nil {
		logrus.Errorf("database connection err: %v", err)
		panic(err)
	}

	var count int
	if err = db.QueryRow("SELECT COUNT(1) FROM information_schema.TABLES WHERE table_schema = 'trojan_panel_db' GROUP BY table_schema;").
		Scan(&count); err != nil && err != sql.ErrNoRows {
		logrus.Errorf("query database err: %v", err)
		panic(err)
	}
	if count == 0 {
		passwordFile := filepath.Join(constant.ConfigPath, "initial-admin-password.txt")
		seed, seedErr := security.PrepareAdminSeed(sqlInitStr, passwordFile)
		if seedErr != nil {
			panic(seedErr)
		}
		if err = SqlInit(seed); err != nil {
			logrus.Errorf("database import err: %v", err)
			panic(err)
		}
		logrus.Warnf("Initial administrator password saved in %s; read it locally and change it after login", passwordFile)
	}

	// 模板配置包含可由管理员维护的多行域名列表，旧版 VARCHAR(512)
	// 无法容纳前后端允许的内容。仅在旧字段容量不足时执行迁移。
	if err = MigrateTemplateConfigColumn(); err != nil {
		logrus.Warnf("template config column migrate err: %v", err)
	}

	// 品牌更名迁移：把旧默认系统名称换为 XWarp（仅替换旧默认值，不影响管理员自定义的名称）
	if err = MigrateSystemName(); err != nil {
		logrus.Warnf("system name migrate err: %v", err)
	}
}

// MigrateTemplateConfigColumn 扩容模板设置，支持自定义直连和代理域名列表。
func MigrateTemplateConfigColumn() error {
	var capacity sql.NullInt64
	if err := db.QueryRow("SELECT CHARACTER_MAXIMUM_LENGTH FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = 'system' AND COLUMN_NAME = 'template_config'").Scan(&capacity); err != nil {
		return err
	}
	if !capacity.Valid || capacity.Int64 >= 65535 {
		return nil
	}
	const sqlStr = "ALTER TABLE `system` MODIFY COLUMN `template_config` TEXT NOT NULL COMMENT '模板设置'"
	_, err := db.Exec(sqlStr)
	return err
}

// MigrateSystemName 将历史默认系统名称（X Panel / Trojan Panel）迁移为 XWarp
func MigrateSystemName() error {
	const sqlStr = `UPDATE system SET template_config = REPLACE(REPLACE(template_config, '"systemName":"X Panel"', '"systemName":"XWarp"'), '"systemName":"Trojan Panel"', '"systemName":"XWarp"') WHERE template_config LIKE '%"systemName":"X Panel"%' OR template_config LIKE '%"systemName":"Trojan Panel"%'`
	_, err := db.Exec(sqlStr)
	return err
}

func CloseDb() {
	if db != nil {
		if err := db.Close(); err != nil {
			logrus.Errorf("db close err: %v", err)
		}
	}
}

func SqlInit(sqlStr string) error {
	sqls := strings.Split(strings.Replace(sqlStr, "\r\n", "\n", -1), ";\n")
	for _, s := range sqls {
		s = strings.TrimSpace(s)
		if s != "" {
			if _, err := db.Exec(s); err != nil {
				logrus.Errorf("sql execution err: %v", err)
				return err
			}
		}
	}
	return nil
}

var sqlInitStr = "CREATE DATABASE IF NOT EXISTS `trojan_panel_db` DEFAULT CHARACTER SET utf8mb4;\nUSE `trojan_panel_db`;\nDROP TABLE IF EXISTS `account`;\nCREATE TABLE `account` (\n  `id` bigint(10) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `username` varchar(64) NOT NULL DEFAULT '' COMMENT '登录用户名',\n  `pass` varchar(64) NOT NULL DEFAULT '' COMMENT '登录密码',\n  `hash` varchar(64) NOT NULL DEFAULT '' COMMENT 'pass的hash',\n  `quota` bigint(20) NOT NULL DEFAULT '0' COMMENT '配额 单位/byte',\n  `download` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '下载 单位/byte',\n  `upload` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '上传 单位/byte',\n  `ip_limit` tinyint(2) unsigned NOT NULL DEFAULT '3' COMMENT '限制IP设备数',\n  `upload_speed_limit` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '上传限速 单位/byte',\n  `download_speed_limit` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '下载限速 单位/byte',\n  `role_id` bigint(20) unsigned NOT NULL DEFAULT '3' COMMENT '角色id 1/系统管理员 3/普通用户',\n  `email` varchar(64) NOT NULL DEFAULT '' COMMENT '邮箱',\n  `preset_expire` int(10) unsigned NOT NULL DEFAULT '0' COMMENT '预设过期时长',\n  `preset_quota` bigint(20) NOT NULL DEFAULT '0' COMMENT '预设配额',\n  `last_login_time` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '最后一次登录时间',\n  `expire_time` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '过期时间',\n  `deleted` tinyint(1) unsigned NOT NULL DEFAULT '0' COMMENT '是否禁用 0/正常 1/禁用',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COMMENT='账户';\nLOCK TABLES `account` WRITE;\nINSERT INTO `account` VALUES (1,'sysadmin','tFjD2X1F6i9FfWp2GDU5Vbi1conuaChDKIYbw9zMFrqvMoSz','4366294571b8b267d9cf15b56660f0a70659568a86fc270a52fdc9e5',-1,0,0,3,0,0,1,'',0,0,0,4078656000000,0,'2022-04-01 00:00:00','2022-04-01 00:00:00');\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `black_list`;\nCREATE TABLE `black_list` (\n  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `ip` varchar(64) NOT NULL DEFAULT '' COMMENT 'IP地址',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='黑名单';\nLOCK TABLES `black_list` WRITE;\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `casbin_rule`;\nCREATE TABLE `casbin_rule` (\n  `p_type` varchar(32) NOT NULL DEFAULT '',\n  `v0` varchar(255) NOT NULL DEFAULT '',\n  `v1` varchar(255) NOT NULL DEFAULT '',\n  `v2` varchar(255) NOT NULL DEFAULT '',\n  `v3` varchar(255) NOT NULL DEFAULT '',\n  `v4` varchar(255) NOT NULL DEFAULT '',\n  `v5` varchar(255) NOT NULL DEFAULT '',\n  KEY `idx_casbin_rule` (`p_type`,`v0`,`v1`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;\nLOCK TABLES `casbin_rule` WRITE;\nINSERT INTO `casbin_rule` VALUES ('p','sysadmin','/api/account/selectAccountById','GET','','',''),('p','sysadmin','/api/account/createAccount','POST','','',''),('p','sysadmin','/api/account/getAccountInfo','GET','','',''),('p','sysadmin','/api/account/selectAccountPage','GET','','',''),('p','sysadmin','/api/account/deleteAccountById','POST','','',''),('p','sysadmin','/api/account/updateAccountPass','POST','','',''),('p','sysadmin','/api/account/updateAccountProperty','POST','','',''),('p','sysadmin','/api/account/updateAccountById','POST','','',''),('p','sysadmin','/api/account/logout','POST','','',''),('p','sysadmin','/api/account/clashSubscribe','GET','','',''),('p','sysadmin','/api/account/clashSubscribeForSb','GET','','',''),('p','sysadmin','/api/account/resetAccountDownloadAndUpload','POST','','',''),('p','sysadmin','/api/account/exportAccount','POST','','',''),('p','sysadmin','/api/account/importAccount','POST','','',''),('p','sysadmin','/api/account/createAccountBatch','POST','','',''),('p','sysadmin','/api/account/exportAccountUnused','POST','','',''),('p','sysadmin','/api/role/selectRoleList','GET','','',''),('p','sysadmin','/api/node/selectNodeById','GET','','',''),('p','sysadmin','/api/node/selectNodeInfo','GET','','',''),('p','sysadmin','/api/node/createNode','POST','','',''),('p','sysadmin','/api/node/selectNodePage','GET','','',''),('p','sysadmin','/api/node/deleteNodeById','POST','','',''),('p','sysadmin','/api/node/updateNodeById','POST','','',''),('p','sysadmin','/api/node/nodeQRCode','POST','','',''),('p','sysadmin','/api/node/nodeURL','POST','','',''),('p','sysadmin','/api/nodeType/selectNodeTypeList','GET','','',''),('p','sysadmin','/api/node/nodeDefault','GET','','',''),('p','sysadmin','/api/dashboard/panelGroup','GET','','',''),('p','sysadmin','/api/dashboard/trafficRank','GET','','',''),('p','sysadmin','/api/system/selectSystemByName','GET','','',''),('p','sysadmin','/api/system/updateSystemById','POST','','',''),('p','sysadmin','/api/system/uploadWebFile','POST','','',''),('p','sysadmin','/api/system/uploadLogo','POST','','',''),('p','sysadmin','/api/blackList/selectBlackListPage','GET','','',''),('p','sysadmin','/api/blackList/deleteBlackListByIp','POST','','',''),('p','sysadmin','/api/blackList/createBlackList','POST','','',''),('p','sysadmin','/api/emailRecord/selectEmailRecordPage','GET','','',''),('p','sysadmin','/api/nodeServer/selectNodeServerById','GET','','',''),('p','sysadmin','/api/nodeServer/createNodeServer','POST','','',''),('p','sysadmin','/api/nodeServer/selectNodeServerPage','GET','','',''),('p','sysadmin','/api/nodeServer/deleteNodeServerById','POST','','',''),('p','sysadmin','/api/nodeServer/updateNodeServerById','POST','','',''),('p','sysadmin','/api/nodeServer/selectNodeServerList','GET','','',''),('p','sysadmin','/api/nodeServer/nodeServerState','GET','','',''),('p','sysadmin','/api/nodeServer/exportNodeServer','POST','','',''),('p','sysadmin','/api/nodeServer/importNodeServer','POST','','',''),('p','sysadmin','/api/fileTask/selectFileTaskPage','GET','','',''),('p','sysadmin','/api/fileTask/deleteFileTaskById','POST','','',''),('p','sysadmin','/api/fileTask/downloadFileTask','POST','','',''),('p','sysadmin','/api/fileTask/downloadTemplate','POST','','',''),('p','user','/api/account/getAccountInfo','GET','','',''),('p','user','/api/account/updateAccountPass','POST','','',''),('p','user','/api/account/updateAccountProperty','POST','','',''),('p','user','/api/account/logout','POST','','',''),('p','user','/api/account/clashSubscribe','GET','','',''),('p','user','/api/node/selectNodeInfo','GET','','',''),('p','user','/api/node/selectNodePage','GET','','',''),('p','user','/api/node/nodeQRCode','POST','','',''),('p','user','/api/node/nodeURL','POST','','',''),('p','user','/api/nodeType/selectNodeTypeList','GET','','',''),('p','user','/api/node/nodeDefault','GET','','',''),('p','user','/api/dashboard/panelGroup','GET','','',''),('p','user','/api/dashboard/trafficRank','GET','','',''),('p','user','/api/nodeServer/selectNodeServerList','GET','','',''),('p','user','/api/nodeServer/nodeServerState','GET','','','');\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `email_record`;\nCREATE TABLE `email_record` (\n  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `to_email` varchar(64) NOT NULL DEFAULT '' COMMENT '收件人邮箱',\n  `subject` varchar(64) NOT NULL DEFAULT '' COMMENT '主题',\n  `content` varchar(255) NOT NULL DEFAULT '' COMMENT '内容',\n  `state` tinyint(1) unsigned NOT NULL DEFAULT '0' COMMENT '状态 0/未发送 1/发送成功 -1/发送失败',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='邮件发送记录';\nLOCK TABLES `email_record` WRITE;\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `file_task`;\nCREATE TABLE `file_task` (\n  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `name` varchar(64) NOT NULL DEFAULT '' COMMENT '文件名称',\n  `path` varchar(128) NOT NULL DEFAULT '' COMMENT '文件路径',\n  `type` tinyint(2) unsigned NOT NULL DEFAULT '1' COMMENT '类型 1/用户导入 2/服务器导入 3/用户导出 4/服务器导出',\n  `status` tinyint(1) NOT NULL DEFAULT '0' COMMENT '状态 -1/失败 0/等待 1/正在执行 2/成功',\n  `err_msg` varchar(128) NOT NULL DEFAULT '' COMMENT '错误信息',\n  `account_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '账户id',\n  `account_username` varchar(64) NOT NULL DEFAULT '' COMMENT '账户登录用户名',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='文件任务';\nLOCK TABLES `file_task` WRITE;\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `node`;\nCREATE TABLE `node` (\n  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `node_server_id` bigint(20) NOT NULL DEFAULT '0' COMMENT '服务器id',\n  `node_sub_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '节点分表id',\n  `node_type_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '节点类型id',\n  `name` varchar(64) NOT NULL DEFAULT '' COMMENT '名称',\n  `node_server_ip` varchar(64) NOT NULL DEFAULT '' COMMENT 'IP地址',\n  `node_server_grpc_port` int(10) unsigned NOT NULL DEFAULT '8100' COMMENT 'gRPC端口',\n  `domain` varchar(64) NOT NULL DEFAULT '' COMMENT '域名',\n  `port` int(10) unsigned NOT NULL DEFAULT '443' COMMENT '端口',\n  `priority` int(11) NOT NULL DEFAULT '100' COMMENT '优先级',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='节点';\nLOCK TABLES `node` WRITE;\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `node_hysteria`;\nCREATE TABLE `node_hysteria` (\n  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `protocol` varchar(32) NOT NULL DEFAULT 'udp' COMMENT '协议名称 udp/faketcp',\n  `obfs` varchar(64) NOT NULL DEFAULT '' COMMENT '混淆密码',\n  `up_mbps` int(10) NOT NULL DEFAULT '100' COMMENT '单客户端最大上传速度 单位:Mbps',\n  `down_mbps` int(10) NOT NULL DEFAULT '100' COMMENT '单客户端最大下载速度 单位:Mbps',\n  `server_name` varchar(64) NOT NULL DEFAULT '' COMMENT '用于验证服务端证书的 hostname',\n  `insecure` tinyint(1) NOT NULL DEFAULT 0 COMMENT '忽略一切证书错误',\n  `fast_open` tinyint(1) NOT NULL DEFAULT 0 COMMENT '启用 Fast Open (降低连接建立延迟)',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Hysteria节点';\nLOCK TABLES `node_hysteria` WRITE;\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `node_hysteria2`;\nCREATE TABLE `node_hysteria2` (\n  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `obfs_password` varchar(64) NOT NULL DEFAULT '' COMMENT '混淆密码',\n  `up_mbps` int(10) NOT NULL DEFAULT '100' COMMENT '单客户端最大上传速度 单位:Mbps',\n  `down_mbps` int(10) NOT NULL DEFAULT '100' COMMENT '单客户端最大下载速度 单位:Mbps',\n  `server_name` varchar(64) NOT NULL DEFAULT '' COMMENT '用于验证服务端证书的 hostname',\n  `insecure` tinyint(1) NOT NULL DEFAULT '0' COMMENT '忽略一切证书错误',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Hysteria2节点';\nLOCK TABLES `node_hysteria2` WRITE;\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `node_server`;\nCREATE TABLE `node_server` (\n  `id` bigint(20) NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `ip` varchar(64) NOT NULL DEFAULT '' COMMENT '服务器IP',\n  `name` varchar(64) NOT NULL DEFAULT '' COMMENT '服务器名称',\n  `grpc_port` int(10) unsigned NOT NULL DEFAULT '8100' COMMENT 'gRPC端口',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='服务器';\nLOCK TABLES `node_server` WRITE;\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `node_trojan_go`;\nCREATE TABLE `node_trojan_go` (\n  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `sni` varchar(64) NOT NULL DEFAULT '' COMMENT 'sni',\n  `mux_enable` tinyint(1) unsigned NOT NULL DEFAULT '1' COMMENT '是否开启多路复用 0/关闭 1/开启',\n  `websocket_enable` tinyint(1) unsigned NOT NULL DEFAULT '0' COMMENT '是否开启websocket 0/否 1/是',\n  `websocket_path` varchar(64) NOT NULL DEFAULT 'trojan-panel-websocket-path' COMMENT 'websocket路径',\n  `websocket_host` varchar(64) NOT NULL DEFAULT '' COMMENT 'websocket host',\n  `ss_enable` tinyint(1) unsigned NOT NULL DEFAULT '0' COMMENT '是否开启ss加密 0/否 1/是',\n  `ss_method` varchar(32) NOT NULL DEFAULT 'AES-128-GCM' COMMENT 'ss加密方式',\n  `ss_password` varchar(64) NOT NULL DEFAULT '' COMMENT 'ss密码',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='TrojanGO节点';\nLOCK TABLES `node_trojan_go` WRITE;\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `node_type`;\nCREATE TABLE `node_type` (\n  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `name` varchar(32) NOT NULL DEFAULT '' COMMENT '名称',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB AUTO_INCREMENT=6 DEFAULT CHARSET=utf8mb4 COMMENT='节点类型';\nLOCK TABLES `node_type` WRITE;\nINSERT INTO `node_type` VALUES (1,'xray','2022-04-01 00:00:00','2022-04-01 00:00:00'),(2,'trojan-go','2022-04-01 00:00:00','2022-04-01 00:00:00'),(3,'hysteria','2022-04-01 00:00:00','2022-04-01 00:00:00'),(4,'naiveproxy','2022-04-01 00:00:00','2022-04-01 00:00:00'),(5,'hysteria2','2022-04-01 00:00:00','2022-04-01 00:00:00');\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `node_xray`;\nCREATE TABLE `node_xray` (\n  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `protocol` varchar(32) NOT NULL DEFAULT '' COMMENT '协议名称',\n  `xray_flow` varchar(32) NOT NULL DEFAULT '' COMMENT 'Xray流控',\n  `xray_ss_method` varchar(32) NOT NULL DEFAULT 'aes-256-gcm' COMMENT 'Xray Shadowsocks加密方式',\n  `reality_pbk` varchar(64) NOT NULL DEFAULT '' COMMENT 'reality的公钥',\n  `settings` varchar(1024) NOT NULL DEFAULT '' COMMENT 'settings',\n  `stream_settings` varchar(1024) NOT NULL DEFAULT '' COMMENT 'streamSettings',\n  `tag` varchar(64) NOT NULL DEFAULT '' COMMENT 'tag',\n  `sniffing` varchar(256) NOT NULL DEFAULT '' COMMENT 'sniffing',\n  `allocate` varchar(256) NOT NULL DEFAULT '' COMMENT 'allocate',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COMMENT='Xray节点';\nLOCK TABLES `node_xray` WRITE;\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `role`;\nCREATE TABLE `role` (\n  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `name` varchar(16) NOT NULL DEFAULT '' COMMENT '名称',\n  `desc` varchar(16) NOT NULL DEFAULT '' COMMENT '描述',\n  `parent_id` bigint(20) unsigned NOT NULL DEFAULT '0' COMMENT '父级id',\n  `path` varchar(128) NOT NULL DEFAULT '' COMMENT '路径',\n  `level` int(11) unsigned NOT NULL DEFAULT '0' COMMENT '等级',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`),\n  KEY `role_name_index` (`name`)\n) ENGINE=InnoDB AUTO_INCREMENT=4 DEFAULT CHARSET=utf8mb4 COMMENT='角色';\nLOCK TABLES `role` WRITE;\nINSERT INTO `role` VALUES (1,'sysadmin','System Admin',0,'',1,'2022-04-01 00:00:00','2022-04-01 00:00:00'),(2,'admin','Admin',1,'1-',2,'2022-04-01 00:00:00','2022-04-01 00:00:00'),(3,'user','User',2,'1-2-',3,'2022-04-01 00:00:00','2022-04-01 00:00:00');\nUNLOCK TABLES;\nDROP TABLE IF EXISTS `system`;\nCREATE TABLE `system` (\n  `id` bigint(20) unsigned NOT NULL AUTO_INCREMENT COMMENT '自增主键',\n  `name` varchar(16) NOT NULL DEFAULT '' COMMENT '系统名称',\n  `account_config` varchar(512) NOT NULL DEFAULT '' COMMENT '用户设置',\n  `email_config` varchar(512) NOT NULL DEFAULT '' COMMENT '系统邮箱设置',\n  `template_config` text NOT NULL COMMENT '模板设置',\n  `create_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP COMMENT '创建时间',\n  `update_time` datetime NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP COMMENT '更新时间',\n  PRIMARY KEY (`id`)\n) ENGINE=InnoDB AUTO_INCREMENT=2 DEFAULT CHARSET=utf8mb4 COMMENT='系统设置';\nLOCK TABLES `system` WRITE;\nINSERT INTO `system` VALUES (1,'trojan-panel','{\\\"registerEnable\\\":1,\\\"registerQuota\\\":0,\\\"registerExpireDays\\\":0,\\\"resetDownloadAndUploadMonth\\\":0,\\\"trafficRankEnable\\\":1,\\\"captchaEnable\\\":0}','{\\\"expireWarnEnable\\\":0,\\\"expireWarnDay\\\":0,\\\"emailEnable\\\":0,\\\"emailHost\\\":\\\"\\\",\\\"emailPort\\\":0,\\\"emailUsername\\\":\\\"\\\",\\\"emailPassword\\\":\\\"\\\"}','{\\\"systemName\\\":\\\"XWarp\\\"}','2022-04-01 00:00:00','2022-04-01 00:00:00');\nUNLOCK TABLES;"
