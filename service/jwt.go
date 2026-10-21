package service

import (
	"errors"
	"github.com/golang-jwt/jwt"
	"time"
	"trojan-panel/dao"
	"trojan-panel/dao/redis"
	"trojan-panel/model/constant"
	"trojan-panel/model/vo"
	"trojan-panel/security"
)

// TokenExpireDuration 过期时间默认12小时
const TokenExpireDuration = time.Hour * 12

type MyClaims struct {
	AccountVo vo.AccountVo `json:"accountVo"`
	jwt.StandardClaims
}

// GenToken 生成Token
func GenToken(accountVo vo.AccountVo) (string, error) {
	id, err := security.RandomPassword(32)
	if err != nil {
		return "", err
	}
	// 创建一个我们自己的声明
	c := MyClaims{
		// 自定义字段
		AccountVo: accountVo,
		StandardClaims: jwt.StandardClaims{
			Id:       id,
			IssuedAt: time.Now().Unix(),
			// 过期时间
			ExpiresAt: time.Now().Add(TokenExpireDuration).Unix(),
			// 签发人
			Issuer: "trojan-panel",
		},
	}
	// 使用指定的签名方法创建签名对象
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	// 使用指定的secret签名并获得完整的编码后的字符串token
	mySecret, err := GetJWTKey()
	if err != nil {
		return "", errors.New(constant.SysError)
	}
	return token.SignedString(mySecret)
}

// ParseToken 解析Token
func ParseToken(tokenString string) (*MyClaims, error) {
	mySecret, err := GetJWTKey()
	if err != nil {
		return nil, errors.New(constant.SysError)
	}
	// 解析Token
	token, err := jwt.ParseWithClaims(tokenString, &MyClaims{}, func(token *jwt.Token) (i interface{}, err error) {
		if token.Method != jwt.SigningMethodHS256 {
			return nil, errors.New(constant.IllegalTokenError)
		}
		return mySecret, nil
	})
	if err != nil {
		return nil, errors.New(constant.IllegalTokenError)
	}
	// 校验Token
	if claims, ok := token.Claims.(*MyClaims); ok && token.Valid {
		return claims, nil
	}
	return nil, errors.New(constant.TokenExpiredError)
}

func GetJWTKey() ([]byte, error) {
	key := dao.Security.JWTKey()
	// The unchanged core reads this shared key from Redis for gRPC authentication.
	current, err := redis.Client.String.Get("trojan-panel:jwt-key").Bytes()
	if err == nil && string(current) == string(key) {
		return key, nil
	}
	if _, err := redis.Client.String.Set("trojan-panel:jwt-key", key).Result(); err != nil {
		return nil, errors.New(constant.SysError)
	}
	return key, nil
}
