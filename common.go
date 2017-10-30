package main

import (
	"math/rand"
	"time"
	"strings"
	"strconv"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/url"
	"fmt"
	"errors"
	"crypto/md5"
	"io"
)

type Comm interface {
	// 	微信分配的公众账号ID（企业号corpid即为此appId）
	GetAppId() string
	// 微信支付分配的商户号
	GetMchId() string
	// 随机字符串
	GetRandNum() string
	// 扫码支付授权码，设备读取用户微信中的条码或者二维码信息
	GetAuthCode() string
	// 商户平台设置的密钥
	GetAuthKey() string
	//
	ParseUrl(string, ...interface{}) (string, error)
	//
	Signature()
}

type comm struct {
	Key string
	Count int
}

func (c comm) GetRandNum() string {
	nums := make([]string, 0)
	for len(nums) < c.Count {
		// 随机数种子
		r := rand.New(rand.NewSource(time.Now().UnixNano()))
		//生成随机数
		num := r.Intn(100)
		n := strconv.Itoa(num)
		//查重
		exist := false
		for _, v := range nums {
			if v == n {
				exist = true
				break
			}
		}
		// 不存在append
		if !exist {
			nums = append(nums, n)
		}
	}
	return strings.Join(nums, "")
}

func (c comm) GetAppId() string {
	return c.Key
}
func (c comm) GetMchId() string {
	return c.Key
}
func (c comm) GetAuthCode() string {
	return c.Key
}
func (c comm) GetAuthKey() string {
	return c.Key
}

func (c comm) ParseUrl(urlStr string, args ...interface{}) (string, error) {
	uq, err := url.Parse(urlStr)
	if err != nil {
		fmt.Println("url parse :", err)
	}
	query := uq.Query()
	if len(args) == 0 {
		return "", errors.New("param is not allowed. ")
	}
	var key, value string
	for i, arg := range args {
		if i%2 == 1 {
			value = arg.(string)
			// 如果参数的值为空不参与签名
			if value != "" {
				query.Add(key, value)
			}
		} else {
			// 参数名区分大小写
			key = arg.(string)
		}
	}
	// 参数名ASCII码从小到大排序（字典序）
	uq.RawQuery = query.Encode()
	fmt.Println("url :", uq.String())
	return uq.String(), nil
}

/*
	验证调用返回或微信主动通知签名时，传送的sign参数不参与签名，将生成的签名与该sign值作校验
	微信接口可能增加字段，验证签名时必须支持增加的扩展字段
 */
func (c comm) Signature() {
	urlStr, _ := c.ParseUrl("", "", "")
	params := strings.Split(urlStr, "?")
	var param string
	for _, p := range params {
		if !strings.Contains(p, "http") {
			param = p
			break
		}
	}
	// 拼接API密钥
	stringSignTemp := param + "&key=" + c.GetAuthKey()
	// MD5签名加密
	sign := Md5String(stringSignTemp)
	// HMAC-SHA256签名方式
	sign = Hmac256(sign, c.GetAuthKey())
}

// HmacSHA256 哈希算法
func Hmac256(message, secret string) string {
	key := []byte(secret)
	h := hmac.New(sha256.New, key)
	h.Write([]byte(message))
	return strings.ToUpper(base64.StdEncoding.EncodeToString(h.Sum(nil)))
}

// MD5 加密
func Md5String(str string) (md5Str string) {
	h := md5.New()
	io.WriteString(h, str)
	return strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil)))
}