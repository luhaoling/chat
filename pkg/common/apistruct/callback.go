package apistruct

import common "github.com/OpenIMSDK/protocol/sdkws"

type CallbackBeforePushReq struct {
	UserStatusBatchCallbackReq
	*common.OfflinePushInfo
	ClientMsgID string   `json:"clientMsgID"`
	SendID      string   `json:"sendID"`
	GroupID     string   `json:"groupID"`
	ContentType int32    `json:"contentType"`
	SessionType int32    `json:"sessionType"`
	AtUserIDs   []string `json:"atUserIDList"`
	Content     string   `json:"content"`
}

type CallbackBeforePushResp struct {
	CommonCallbackResp
	UserIDs         []string                `json:"userIDList"`
	OfflinePushInfo *common.OfflinePushInfo `json:"offlinePushInfo"`
}

type UserStatusBatchCallbackReq struct {
	UserStatusBaseCallback
	UserIDList []string `json:"userIDList"`
}

type UserStatusBaseCallback struct {
	CallbackCommand string `json:"callbackCommand"`
	OperationID     string `json:"operationID"`
	PlatformID      int    `json:"platformID"`
	Platform        string `json:"platform"`
}
