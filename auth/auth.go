package auth

import (
	"net/http"
	"github.com/mholt/caddy/caddyhttp/httpserver"
	"fmt"
	"strings"
	"github.com/dgrijalva/jwt-go"
	"errors"
	"strconv"
	"k8s.io/apiserver/pkg/endpoints/request"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apimachinery/pkg/util/sets"
)

type Auth struct {
	Rules []Rule
	Next  httpserver.Handler
}

type Rule struct {
	Path         string
	ExceptedPath []string
}

type User struct {
	Username string                  `json:"username"`
	UID      string                  `json:"uid"`
	Groups   *[]string               `json:"groups,omitempty"`
	Extra    *map[string]interface{} `json:"extra,omitempty"`
}

const jenkinsAPIBase = "/apis/jenkins.kubesphere.io"

var requestInfoFactory = request.RequestInfoFactory{
	APIPrefixes:          sets.NewString("api", "apis"),
	GrouplessAPIPrefixes: sets.NewString("api")}

func (h *Auth) ServeHTTP(resp http.ResponseWriter, req *http.Request) (int, error) {

	for _, r := range h.Rules {

		skip := false

		for _, path := range r.ExceptedPath {
			if httpserver.Path(req.URL.Path).Matches(path) {
				skip = true
				break
			}
		}

		if skip {
			continue
		}

		if httpserver.Path(req.URL.Path).Matches(r.Path) {

			uToken, err := extractToken(req)

			if err != nil {
				return handleUnauthorized(resp, req, err.Error()), nil
			}

			token, err := validate(uToken)

			if err != nil {
				return handleUnauthorized(resp, req, err.Error()), nil
			}

			r, err := injectContext(uToken, token, req)

			if err != nil {
				return handleUnauthorized(resp, req, err.Error()), nil
			} else {
				req = r
			}
		}
	}

	return h.Next.ServeHTTP(resp, req)
}

func injectContext(uToken string, token *jwt.Token, req *http.Request) (*http.Request, error) {

	payLoad, ok := token.Claims.(jwt.MapClaims)

	if !ok {
		return nil, errors.New("invalid payload")
	}

	for header := range req.Header {
		if strings.HasPrefix(header, "X-Token-") {
			req.Header.Del(header)
		}
	}

	usr := &user.DefaultInfo{}

	username, ok := payLoad["username"].(string)

	if ok && username != "" {
		req.Header.Set("X-Token-Username", username)
		usr.Name = username
	}

	uid := payLoad["uid"]

	if uid != nil {
		switch uid.(type) {
		case int:
			req.Header.Set("X-Token-UID", strconv.Itoa(uid.(int)))
			usr.UID = strconv.Itoa(uid.(int))
			break
		case string:
			req.Header.Set("X-Token-UID", uid.(string))
			usr.UID = uid.(string)
			break
		}
	}

	groups, ok := payLoad["groups"].([]string)
	if ok && len(groups) > 0 {
		req.Header.Set("X-Token-Groups", strings.Join(groups, ","))
		usr.Groups = groups
	}

	if httpserver.Path(req.URL.Path).Matches(jenkinsAPIBase) {
		req.SetBasicAuth(username, uToken)
	}

	//TODO extra
	//extra := payLoad["extra"]

	context := req.Context()

	context = request.WithUser(context, usr)

	requestInfo, err := requestInfoFactory.NewRequestInfo(req)

	if err == nil {
		context = request.WithRequestInfo(context, requestInfo)
	} else {
		return nil, err
	}

	req = req.WithContext(context)

	return req, nil
}

func validate(uToken string) (*jwt.Token, error) {

	if len(uToken) == 0 {
		return nil, fmt.Errorf("token length is zero")
	}

	token, err := jwt.Parse(uToken, ProvideKey)

	if err != nil {
		return nil, err
	}

	return token, nil
}

func handleUnauthorized(w http.ResponseWriter, r *http.Request, reason string) int {
	message := fmt.Sprintf("Unauthorized,%s", reason)
	w.Header().Add("WWW-Authenticate", message)
	return http.StatusUnauthorized
}

func extractToken(r *http.Request) (string, error) {

	jwtHeader := strings.Split(r.Header.Get("Authorization"), " ")
	if jwtHeader[0] == "Bearer" && len(jwtHeader) == 2 {
		return jwtHeader[1], nil
	}

	jwtCookie, err := r.Cookie("token")

	if err == nil {
		return jwtCookie.Value, nil
	}

	jwtQuery := r.URL.Query().Get("token")
	if jwtQuery != "" {
		return jwtQuery, nil
	}

	return "", fmt.Errorf("no token found")
}
