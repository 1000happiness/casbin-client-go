package util

import (
	"encoding/base64"
	"net/http"
	"strings"
)

func WrapperAuditInfo(req *http.Request, approvers []string, message string) *http.Request {
	if len(approvers) > 0 {
		req.Header.Set("x-casbin-approvers", strings.Join(approvers, ","))
	}
	if message != "" {
		message_b64 := base64.StdEncoding.EncodeToString([]byte(message))
		req.Header.Set("x-casbin-message", message_b64)
	}
	return req
}
