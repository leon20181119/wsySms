package main

import (
	"bytes"
	"crypto/des"
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"time"
	"unsafe"
)

/**
网宿云发送短信验证码
*/
func main() {
	//auth-user:由网宿云提供
	authUser := "cqwqk"
	//user-key:由网宿云提供
	userkey := "eOLqF7gJ6dgDDxj4"

	timeStamp := time.Now()
	//auth-timeStamp
	authTimeStamp := timeStamp.Format("20060102150405")

	//auth-signature
	//1,对 userKey 做 md5 加密，得到十六进制表示的 hex 值。
	md5Ctx := md5.New()
	md5Ctx.Write([]byte(userkey))
	cipherStr := md5Ctx.Sum(nil)
	hex1 := hex.EncodeToString(cipherStr)

	//2.将 hex 转为小写，截取前 24 位，得到 secret
	hex2 := strings.ToLower(hex1)
	secret := hex2[0:24]

	data := fmt.Sprint("auth-timeStamp=", authTimeStamp, "&auth-user=", authUser)

	//3.获取认证签名
	authSignatureByte, err := DesEncrypt([]byte(data), []byte(secret))
	if err != nil {
		fmt.Println("获取认证签名失败。")
		return
	}

	//对结果做base64
	authSignature := base64.StdEncoding.EncodeToString(authSignatureByte)
	fmt.Println(authSignature)

	//生成短信验证码
	rnd := rand.New(rand.NewSource(time.Now().UnixNano()))
	smsCode := fmt.Sprintf("%06v", rnd.Int31n(1000000))

	//4.发送短信
	smsBodyJson := &SmsBody{
		2,
		"【人人付】您的验证码为:" + smsCode,
		// "8618503088056",
		"639215063282",
		"",
	}
	bytesData, err := json.Marshal(smsBodyJson)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	form := url.Values{}
	form["sms"] = []string{string(bytesData)}

	// encodeurl := url.QueryEscape(string(bytesData)) //URLEncode
	reader := strings.NewReader(form.Encode())
	url := "https://sms.server.matocloud.com/sms/is/api/sms/simple/sendSms"
	request, err := http.NewRequest("POST", url, reader)
	if err != nil {
		fmt.Println(err.Error())
		return
	}

	request.Header.Set("Content-Type", "application/x-www-form-urlencoded;charset=utf-8")
	request.Header.Set("auth-user", authUser)
	request.Header.Set("auth-timeStamp", authTimeStamp)
	request.Header.Set("auth-signature", authSignature)

	client := http.Client{}

	resp, err := client.Do(request)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	respBytes, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println(err.Error())
		return
	}
	//byte数组直接转成string，优化内存
	str := (*string)(unsafe.Pointer(&respBytes))
	fmt.Println(*str)

}

type Sms struct {
	Sms SmsBody `json:sms`
}

type SmsBody struct {
	Type    int64  `json:"type"`    //2
	Content string `json:"content"` //验证码，包含前置签名
	Phone   string `json:"phone"`   // 手机号码
	ExtCode string `json:"extCode"`
}

func PKCS5Padding(ciphertext []byte, blockSize int) []byte {
	padding := blockSize - len(ciphertext)%blockSize
	padtext := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(ciphertext, padtext...)
}

func PKCS5UnPadding(origData []byte) []byte {
	length := len(origData)
	unpadding := int(origData[length-1])
	return origData[:(length - unpadding)]
}

func DesEncrypt(src, key []byte) ([]byte, error) {
	// block, err := des.NewCipher(key)
	block, err := des.NewTripleDESCipher(key)
	if err != nil {
		return nil, err
	}
	bs := block.BlockSize()
	src = PKCS5Padding(src, bs)
	if len(src)%bs != 0 {
		return nil, errors.New("Need a multiple of the blocksize")
	}
	out := make([]byte, len(src))
	dst := out
	for len(src) > 0 {
		block.Encrypt(dst, src[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}
	return out, nil
}

func DesDecrypt(src, key []byte) ([]byte, error) {
	block, err := des.NewCipher(key)
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(src))
	dst := out
	bs := block.BlockSize()
	if len(src)%bs != 0 {
		return nil, errors.New("crypto/cipher: input not full blocks")
	}
	for len(src) > 0 {
		block.Decrypt(dst, src[:bs])
		src = src[bs:]
		dst = dst[bs:]
	}
	out = PKCS5UnPadding(out)
	return out, nil
}
