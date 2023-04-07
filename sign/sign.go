package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"market-sdk/modal"
)

var (
	DingBlockPubKey = `盯链公钥(开放平台获得)`
	UserPrivateKey  = `您的私钥`
	RsaSign         = rsaSign{
		DingBlockPubKey: DingBlockPubKey,
		UserPrivateKey:  UserPrivateKey,
	}
	AesSign = aesSign{AppId: "您的AppId", appSecret: "您的AppSecret"}
)

type Sign interface {
	Sign(data string) (string, error)
	Verify(originalData, signData string) error
}

type rsaSign struct {
	DingBlockPubKey string
	UserPrivateKey  string
}
type aesSign struct {
	AppId     string
	appSecret string
}

func (aesSign) GetSignStr(bizData string) {
	return
}

func (a *aesSign) Encrypt(plainText string) ([]byte, error) {
	return modal.AesEcbEncrypt([]byte(plainText), []byte(a.appSecret))
}

func (a *aesSign) Decrypt(signData []byte) (originalData []byte, err error) {
	return modal.AesEcbDecrypt(signData, []byte(a.appSecret))
}

func (r *rsaSign) baseSign(s string) (string, error) {
	fmt.Printf("【盯链】签名字符串:  %s \n", s)
	decodeString, _ := base64.StdEncoding.DecodeString(r.UserPrivateKey)
	privateKey, err := x509.ParsePKCS8PrivateKey(decodeString)
	if err != nil {
		fmt.Println("ParsePKCS8PrivateKey err", err)
		return "", err
	}
	h := sha256.New()
	h.Write([]byte(s))
	hash := h.Sum(nil)
	signature, err := rsa.SignPKCS1v15(rand.Reader, privateKey.(*rsa.PrivateKey), crypto.SHA256, hash)
	if err != nil {
		fmt.Printf("Error from signing: %s\n", err)
		return "", err
	}
	out := base64.StdEncoding.EncodeToString(signature)
	//out := hex.EncodeToString(signature)
	return out, nil
}

func (r *rsaSign) ResponseSign(data modal.PublicResponse) (string, error) {
	s := fmt.Sprintf("bizData=%s&code=%d&msg=%s&nonce=%s&timestamp=%d", data.BizData, data.Code, data.Msg, data.Nonce, data.Timestamp)
	fmt.Printf("【盯链】签名字符串:  %s \n", s)
	return r.baseSign(s)
}

func (r *rsaSign) RequestSign(data modal.PublicRequest) (string, error) {
	s := fmt.Sprintf("appId=%s&bizData=%s&method=%s&nonce=%s&timestamp=%d", data.AppId, data.BizData, data.Method, data.Nonce, data.Timestamp)
	fmt.Printf("【盯链】签名字符串:  %s \n", s)
	return r.baseSign(s)
}

func (r *rsaSign) Verify(originalData, signData string) error {
	sign, err := base64.StdEncoding.DecodeString(signData)
	if err != nil {
		println(err.Error())
		return err
	}
	public, _ := base64.StdEncoding.DecodeString(r.DingBlockPubKey)
	pub, err := x509.ParsePKIXPublicKey(public)
	if err != nil {
		println(err.Error())
		return err
	}
	hash := sha256.New()
	hash.Write([]byte(originalData))
	return rsa.VerifyPKCS1v15(pub.(*rsa.PublicKey), crypto.SHA256, hash.Sum(nil), sign)
}
