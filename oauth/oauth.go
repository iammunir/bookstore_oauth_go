package oauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"

	resty "github.com/go-resty/resty/v2"
	"github.com/iammunir/bookstore_oauth_go/utils/errors"
)

const (
	headerXPublic   = "X-Public"
	headerXClientId = "X-Client-Id"
	headerXCallerId = "X-Caller-Id"

	paramAccessToken = "access_token"
)

var (
	oautClient = resty.New()
)

type accessToken struct {
	Id       string `json:"id"`
	UserId   int64  `json:"user_id"`
	ClientId int64  `json:"client_id"`
}

func IsPublic(request *http.Request) bool {
	if request == nil {
		return true
	}
	return request.Header.Get(headerXPublic) == "true"
}

func GetCallerId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	callerId, err := strconv.ParseInt(request.Header.Get(headerXCallerId), 10, 64)
	if err != nil {
		return 0
	}
	return callerId
}

func GetClientId(request *http.Request) int64 {
	if request == nil {
		return 0
	}
	clientId, err := strconv.ParseInt(request.Header.Get(headerXClientId), 10, 64)
	if err != nil {
		return 0
	}
	return clientId
}

func AuthenticateRequest(oauthUrl string, request *http.Request) *errors.RestError {
	if request == nil {
		return nil
	}

	cleanRequest(request)

	accessTokenId := strings.TrimSpace(request.URL.Query().Get(paramAccessToken))
	if accessTokenId == "" {
		return nil
	}

	at, err := getAccessToken(oauthUrl, accessTokenId)
	if err != nil {
		if err.Status == http.StatusNotFound {
			return nil
		}
		return err
	}

	request.Header.Add(headerXClientId, fmt.Sprintf("%v", at.ClientId))
	request.Header.Add(headerXCallerId, fmt.Sprintf("%v", at.UserId))
	return nil
}

func cleanRequest(request *http.Request) {
	if request == nil {
		return
	}
	request.Header.Del(headerXClientId)
	request.Header.Del(headerXCallerId)
}

func getAccessToken(oauthUrl string, accessTokenId string) (*accessToken, *errors.RestError) {
	response, errResp := oautClient.R().Get(oauthUrl + accessTokenId)
	if errResp != nil || response == nil {
		return nil, errors.NewInternalServerError(fmt.Sprintf("error when trying to get access token: %s", errResp.Error()))
	}

	if response.StatusCode() > 299 {
		return nil, errors.NewInternalServerError("api error")
	}

	var accessToken accessToken
	if err := json.Unmarshal(response.Body(), &accessToken); err != nil {
		return nil, errors.NewInternalServerError(fmt.Sprintf("error when trying to unmarshall users login response: %s", err.Error()))
	}

	return &accessToken, nil
}
