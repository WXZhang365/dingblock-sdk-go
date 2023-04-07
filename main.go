package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/gin-gonic/gin/binding"
	"github.com/google/uuid"
	"market-sdk/modal"
	"market-sdk/sign"
	"market-sdk/util"
	"time"
)

var (
	PORT = ":8002"
)

func main() {
	r := gin.Default()

	// 连通性测试
	r.POST("/simpleVerify", func(c *gin.Context) {
		fmt.Println("=======处理请求=======")
		simpleVerifyRequest(c)
		fmt.Println("=======处理响应=======")
	})

	/**
	 * 同步用户信息（仅接入秒转H5嵌入需要实现）
	 * 接口文档地址 https://open.dingblock.tech/market/sync-userinfo.html
	 * 嵌入H5文档地址 https://open.dingblock.tech/market/market-h5.html
	 */

	r.POST("/syncUserInfo", func(c *gin.Context) {
		fmt.Println("=======处理请求=======")
		syncUserInfo(c)
		fmt.Println("=======处理响应=======")
	})

	err := r.Run(PORT)
	if err != nil {
		return
	}
}

func syncUserInfo(c *gin.Context) {
	var phoneNum = "用户电话号码"
	var data = modal.PublicRequest{
		AppId:     sign.AesSign.AppId,
		Timestamp: time.Now().UnixMilli(),
		Nonce:     uuid.New().String(),
		Method:    "market.transfer.sync",
	}
	encryptName, err := sign.AesSign.Encrypt("姓名")
	if err != nil {
		panic(err)
	}
	encryptIdCard, err := sign.AesSign.Encrypt("身份证号")

	if err != nil {
		panic(err)
	}
	var bizData = modal.SyncUserInfoBizData{
		PhoneNumber: phoneNum,
		UserId:      "用户id",
		// 姓名及身份证加密方式：AES-256-ECB（PKCS5Padding）
		RealName: base64.StdEncoding.EncodeToString(encryptName),
		IdCard:   base64.StdEncoding.EncodeToString(encryptIdCard),
	}
	marshal, _ := json.Marshal(bizData)
	data.BizData = string(marshal)

	data.Sign, _ = sign.RsaSign.RequestSign(data)
	_, result := util.Request.Post("盯链网关", data)
	var publicArgs modal.PublicResponse
	json.Unmarshal([]byte(result), &publicArgs)
	c.JSON(200, publicArgs.BizData)

}

func simpleVerifyRequest(ctx *gin.Context) {
	var simpleVerify modal.SimpleVerifyRequest
	err := ctx.ShouldBindBodyWith(&simpleVerify, binding.JSON)
	if err != nil {
		return
	}
	requestStr := fmt.Sprintf("appId=%s&bizData=%s&method=%s&nonce=%s&timestamp=%d", simpleVerify.AppId, simpleVerify.BizData, simpleVerify.Method, simpleVerify.Nonce, simpleVerify.Timestamp)
	var simpleResult = modal.PublicResponse{
		BizData:   "{\"result\":true}",
		Code:      200,
		Nonce:     uuid.New().String(),
		Timestamp: time.Now().UnixMilli(),
	}
	if sign.RsaSign.Verify(requestStr, simpleVerify.Sign) == nil {
		simpleResult.Sign, _ = sign.RsaSign.ResponseSign(simpleResult)
		simpleResult.Msg = "验签成功"
		ctx.JSON(200, simpleResult)
	} else {
		simpleResult.Msg = "验签失败"
		ctx.JSON(200, simpleResult)
	}
}
