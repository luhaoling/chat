// Copyright © 2023 OpenIM open source community. All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package callback

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/OpenIMSDK/chat/pkg/common/apistruct"
	"github.com/OpenIMSDK/chat/pkg/common/config"
	"github.com/OpenIMSDK/chat/pkg/proto/admin"
	"github.com/OpenIMSDK/chat/pkg/proto/chat"
	"github.com/OpenIMSDK/chat/pkg/proto/common"
	"github.com/OpenIMSDK/protocol/constant"
	"github.com/OpenIMSDK/tools/errs"
	"github.com/OpenIMSDK/tools/log"
	"github.com/OpenIMSDK/tools/utils"
	"github.com/gin-gonic/gin"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"
)

type SmartQaReq struct {
	Query string `json:"query"`
}

type SmartQaResp struct {
	Data    DataEntity `json:"data"`
	Messge  string     `json:"messge"`
	Retcode int64      `json:"retcode"`
}

type DataEntity struct {
	Answer string        `json:"answer"`
	Source []interface{} `json:"source"`
}

type CustomMsg struct {
	Data        CustomStu `json:"data"`
	Description string    `json:"description"`
	Extension   string    `json:"extension"`
}

type CustomStu struct {
	CustomType int64      `json:"customType"`
	Data       DataEntity `json:"data"`
}

func CallbackExample(c *gin.Context) {
	// 1. Handling callbacks after sending a single chat message
	msgInfo, err := handlingCallbackAfterSendMsg(c)
	if err != nil {
		log.ZError(c, "handlingCallbackAfterSendMsg failed", err)
		return
	}

	log.ZDebug(c, "msgInfo", "msgInfo", msgInfo)

	// 2. If the user receiving the message is a customer service bot, return the message.
	// 2.1 UserID of the robot account
	robotics := "9169530932"

	// 2.2 ChatRobot account validation and determining if messages are text and images
	if msgInfo.SendID == robotics || msgInfo.RecvID != robotics {
		return
	}
	if msgInfo.ContentType != constant.Picture && msgInfo.ContentType != constant.Text {
		return
	}

	// 2.3 Get administrator token
	adminToken, err := getAdminToken(c)
	if err != nil {
		log.ZError(c, "getAdminToken failed", err)
		return
	}

	// 2.4 Get RobotAccount info
	robUser, err := getRobotAccountInfo(c, adminToken.AdminToken, robotics)
	if err != nil {
		log.ZError(c, "getRobotAccountInfo failed", err)
		return
	}
	log.ZDebug(c, "roUser", robUser)

	// 2.5 Constructing Message Field Contents
	mapStruct, err := contextToMap(c, msgInfo)
	if err != nil {
		log.ZError(c, "contextToMap", err)
		return
	}

	// 2.6 call "http://43.134.63.160/smart_qa"
	query, ok := mapStruct["content"].(string)
	log.ZDebug(c, "get im admin token", "query", query)
	if !ok {
		log.ZError(c, "str, ok := any.(string)", errors.New("the query formate is error"))
	}

	martQaReq := &SmartQaReq{
		Query: query,
	}
	martQaResp, err := callSmartQa(c, martQaReq)
	if err != nil {
		log.ZError(c, "callSmartQa failed", err)
	}
	log.ZDebug(c, "martQaResp info", "martQaResp", martQaResp)

	customStu := CustomMsg{
		Data: CustomStu{
			CustomType: 300,
			Data:       martQaResp.Data,
		},
		Description: "",
		Extension:   "",
	}

	log.ZDebug(c, "customStu of CustomMsg", "customStu", customStu)

	dataJSON, err := json.Marshal(customStu.Data)
	if err != nil {
		log.ZError(c, "dataJSON failed", err)
		return
	}

	mapStruct["data"] = string(dataJSON)
	mapStruct["description"] = customStu.Description
	mapStruct["extension"] = customStu.Extension

	log.ZDebug(c, "update the context format", " mapStruct[\"content\"]", mapStruct["content"])

	// 2.7 Send Message
	log.ZDebug(c, "sendMessage_info", "adminToken.ImToken", adminToken.ImToken, "msgInfo", msgInfo, "robUser", robUser, "mapStruct", mapStruct)

	err = sendMessage(c, adminToken.ImToken, msgInfo, robUser, mapStruct)
	if err != nil {
		log.ZError(c, "getRobotAccountInfo failed", err)
		return
	}
}

// struct to map
func convertStructToMap(input interface{}) (map[string]interface{}, error) {
	result := make(map[string]interface{})
	inputType := reflect.TypeOf(input)
	inputValue := reflect.ValueOf(input)

	if inputType.Kind() != reflect.Struct {
		return nil, errors.New("input is not a struct")
	}

	for i := 0; i < inputType.NumField(); i++ {
		field := inputType.Field(i)
		fieldValue := inputValue.Field(i)

		mapKey := field.Tag.Get("mapstructure")
		if mapKey == "" {
			mapKey = field.Name
		}

		mapKey = strings.ToLower(mapKey)
		result[mapKey] = fieldValue.Interface()
	}

	return result, nil
}

func Post(ctx context.Context, url string, header map[string]string, data any, timeout int) (content []byte, err error) {
	var (
		// define http client.
		client = &http.Client{
			Timeout: 15 * time.Second, // max timeout is 15s
		}
	)

	if timeout > 0 {
		var cancel func()
		ctx, cancel = context.WithTimeout(ctx, time.Second*time.Duration(timeout))
		defer cancel()
	}

	jsonStr, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	log.ZDebug(ctx, "jsonStr", "jsonSTr", string(jsonStr))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewBuffer(jsonStr))
	if err != nil {
		return nil, err
	}

	if operationID, _ := ctx.Value(constant.OperationID).(string); operationID != "" {
		req.Header.Set(constant.OperationID, operationID)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	req.Header.Add("content-type", "application/json; charset=utf-8")

	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	result, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return result, nil
}

// handlingCallbackAfterSendMsg Handling callbacks after sending a message
func handlingCallbackAfterSendMsg(c *gin.Context) (*apistruct.CallbackAfterSendSingleMsgReq, error) {

	var req apistruct.CallbackAfterSendSingleMsgReq

	if err := c.BindJSON(&req); err != nil {
		return nil, err
	}

	resp := apistruct.CallbackAfterSendSingleMsgResp{
		CommonCallbackResp: apistruct.CommonCallbackResp{
			ActionCode: 0,
			ErrCode:    200,
			ErrMsg:     "success",
			ErrDlt:     "successful",
			NextCode:   0,
		},
	}
	c.JSON(http.StatusOK, resp)
	return &req, nil
}

func getAdminToken(c *gin.Context) (*apistruct.AdminLoginResp, error) {
	url := "http://127.0.0.1:50009/account/login"
	adminID := config.Config.AdminList[0].AdminID
	paswd := md5.Sum([]byte(adminID))

	adminInput := admin.LoginReq{
		Account:  config.Config.AdminList[0].AdminID,
		Password: hex.EncodeToString(paswd[:]),
	}

	header := make(map[string]string, 2)
	header["operationID"] = "111"

	b, err := Post(c, url, header, adminInput, 10)
	if err != nil {
		return nil, err
	}

	type TokenInfo struct {
		ErrCode int                      `json:"errCode"`
		ErrMsg  string                   `json:"errMsg"`
		ErrDlt  string                   `json:"errDlt"`
		Data    apistruct.AdminLoginResp `json:"data,omitempty"`
	}

	adminOutput := &TokenInfo{}

	if err = json.Unmarshal(b, adminOutput); err != nil {
		return nil, err
	}
	return &apistruct.AdminLoginResp{AdminToken: adminOutput.Data.AdminToken, ImToken: adminOutput.Data.ImToken}, nil
}

// CheckRobotAccount Verify if the robot account exists
func getRobotAccountInfo(c *gin.Context, token, robotics string) (*common.UserPublicInfo, error) {
	header := make(map[string]string)
	header["token"] = token

	url := "http://127.0.0.1:50008/user/find/public"

	searchInput := chat.FindUserPublicInfoReq{
		UserIDs: []string{robotics},
	}

	b, err := Post(c, url, header, searchInput, 10)
	if err != nil {
		return nil, err
	}

	type UserInfo struct {
		ErrCode int                         `json:"errCode"`
		ErrMsg  string                      `json:"errMsg"`
		ErrDlt  string                      `json:"errDlt"`
		Data    chat.FindUserPublicInfoResp `json:"data,omitempty"`
	}
	searchOutput := &UserInfo{}
	if err = json.Unmarshal(b, searchOutput); err != nil {
		return nil, err
	}

	if len(searchOutput.Data.Users) == 0 || searchOutput.Data.Users == nil {
		return nil, err
	}
	return searchOutput.Data.Users[0], nil
}

func contextToMap(c *gin.Context, req *apistruct.CallbackAfterSendSingleMsgReq) (map[string]any, error) {
	text := apistruct.TextElem{}
	picture := apistruct.PictureElem{}
	mapStruct := make(map[string]any)
	var err error
	// Handle message structures
	if req.ContentType == constant.Text {
		err = json.Unmarshal([]byte(req.Content), &text)
		if err != nil {
			return nil, err
		}
		mapStruct["content"] = text.Content
	} else {
		err = json.Unmarshal([]byte(req.Content), &picture)
		if err != nil {
			return nil, err
		}
		if strings.Contains(picture.SourcePicture.Type, "/") {
			arr := strings.Split(picture.SourcePicture.Type, "/")
			picture.SourcePicture.Type = arr[1]
		}

		if strings.Contains(picture.BigPicture.Type, "/") {
			arr := strings.Split(picture.BigPicture.Type, "/")
			picture.BigPicture.Type = arr[1]
		}

		if len(picture.SnapshotPicture.Type) == 0 {
			picture.SnapshotPicture.Type = picture.SourcePicture.Type
		}

		mapStructSnap := make(map[string]interface{})
		if mapStructSnap, err = convertStructToMap(picture.SnapshotPicture); err != nil {
			return nil, errs.Wrap(err)
		}
		mapStruct["snapshotPicture"] = mapStructSnap

		mapStructBig := make(map[string]interface{})
		if mapStructBig, err = convertStructToMap(picture.BigPicture); err != nil {
			return nil, errs.Wrap(err)
		}
		mapStruct["bigPicture"] = mapStructBig

		mapStructSource := make(map[string]interface{})
		if mapStructSource, err = convertStructToMap(picture.SourcePicture); err != nil {
			return nil, errs.Wrap(err)
		}
		mapStruct["sourcePicture"] = mapStructSource
		mapStruct["sourcePath"] = picture.SourcePath
	}
	return mapStruct, nil
}

func sendMessage(c *gin.Context, token string, req *apistruct.CallbackAfterSendSingleMsgReq, rob *common.UserPublicInfo, mapStruct map[string]interface{}) error {
	header := map[string]string{}
	header["token"] = token

	input := &apistruct.SendMsgReq{
		RecvID: req.SendID,
		SendMsg: apistruct.SendMsg{
			SendID:           rob.UserID,
			SenderNickname:   rob.Nickname,
			SenderFaceURL:    rob.FaceURL,
			SenderPlatformID: req.SenderPlatformID,
			Content:          mapStruct,
			ContentType:      110,
			SessionType:      req.SessionType,
			SendTime:         utils.GetCurrentTimestampByMill(), // millisecond
		},
	}

	log.ZDebug(c, "sendMessage_input", "input", input)

	url := "http://127.0.0.1:50002/msg/send_msg"

	// Initiate a post request that calls the interface that sends the message (the bot sends a message to user)
	_, err := Post(c, url, header, input, 10)
	if err != nil {
		return err
	}
	return nil
}

func callSmartQa(c *gin.Context, smartQaRea *SmartQaReq) (*SmartQaResp, error) {
	header := map[string]string{}

	url := "http://43.134.63.160/smart_qa"
	body, err := Post(c, url, header, smartQaRea, 10)
	if err != nil {
		return nil, err
	}

	log.ZDebug(c, "callSmartQa", "body", string(body))

	response := &SmartQaResp{
		Data: DataEntity{
			Answer: "",
			Source: make([]interface{}, 10),
		},
		Messge:  "",
		Retcode: 0,
	}

	err = json.Unmarshal(body, &response)
	if err != nil {
		return nil, fmt.Errorf("json.Unmarshal failed,err:%v", err)
	}

	log.ZDebug(c, "after Unmarshal", "body", response)

	if response.Retcode != 0 {
		return nil, fmt.Errorf("call \"http://43.134.63.160/smart_qa\" error, resp.Retcode:%d", response)
	}

	return response, nil
}
