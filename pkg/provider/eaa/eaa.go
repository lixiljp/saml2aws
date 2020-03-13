package eaa

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"html"
	"io/ioutil"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"regexp"

	"github.com/sirupsen/logrus"
	"github.com/versent/saml2aws/pkg/prompter"

	"github.com/pkg/errors"
	"github.com/versent/saml2aws/pkg/cfg"
	"github.com/versent/saml2aws/pkg/creds"
	"github.com/versent/saml2aws/pkg/provider"

	"encoding/json"
)

// Client is a wrapper representing a EAA SAML client
type Client struct {
	client      *provider.HTTPClient
	mfa         string
	host        string // hostname of login url
	navigatorId string // dummy browser fingerprint
	requireMFABeforeListApp bool
}

// LoginInfo contains xsrf tokens from EAA login page
type LoginInfo struct {
	Xsrf     string
	Xsrfid   string
	Xctx     string
	Xversion string
}

// LoginRequest contains request fields for EAA login api
type LoginRequest struct {
	Navigator string `json:"navigator"`
	Username  string `json:"username"`
	Password  string `json:"password"`
}

// LoginResponse contains response fields for EAA login api
type LoginResponse struct {
	MFA struct {
		App struct {
			Enable bool `json:"enable"`
		} `json:"app"`
	} `json:"mfa"`
}

// AppInfo contains information of a single app from EAA apps
type AppInfo struct {
	Name     string `json:"name"`
	Hostname string `json:"hostname"`
}

// AppsResponse contains response fields for EAA get apps api
type AppsResponse struct {
	Apps []AppInfo `json:"apps"`
}

// NavigateRequest contains request fields for EAA navigate api
type NavigateRequest struct {
	Hostname string `json:"hostname"`
}

// NavigateRequest contains response fields for EAA navigate api
type NavigateResponse struct {
	Navigate struct {
		Url string `json:"url"`
		Body string `json:"body"`
	} `json:"navigate"`
}

// MFASettingsResponse contains response fields for EAA get MFA settings api
type MFASettingsResponse struct {
	MFA struct {
		Settings map [string] interface{} `json:"settings"`
	} `json:"mfa"`
}

// MFAInfo contains the information of MFA method for EAA login
type MFAInfo struct {
	Option   string
	UUID     string // for totp
	Target   string // the readable name of totp method
}

// PushRequest contains request fields for EAA MFA push api
type PushRequest struct {
	Force bool `json:"force"`
	UUID  string `json:"uuid"`
}

// VerifyRequest contains request fields for EAA MFA verify api
type VerifyRequest struct {
	Category string `json:"category"`
	Token    string `json:"token"`
	UUID     string `json:"uuid"`
}

// VerifyRequest contains response fields for EAA MFA verify api
type VerifyResponse struct {
	Response struct {
		Body string `json:"body"`
	} `json:"response"`
}

var logger = logrus.WithField("provider", "eaa")
var xsrfExp = regexp.MustCompile(`<input.+?id="xsrf".+?value="(.+?)"`)
var xsrfidExp = regexp.MustCompile(`<input.+?id="xsrfid".+?value="(.+?)"`)
var xctxExp = regexp.MustCompile(`<input.+?id="xctx".+?value="(.+?)"`)
var xversionExp = regexp.MustCompile(`<input.+?id="xversion".+?value="(.+?)"`)
var samlResponseExp = regexp.MustCompile(`<input.+?name="SAMLResponse".+?value="(.+?)"`)

// New creates a new EAA client
func New(idpAccount *cfg.IDPAccount) (*Client, error) {

	tr := provider.NewDefaultTransport(idpAccount.SkipVerify)

	// http client will create with cookie jar which required by EAA
	client, err := provider.NewHTTPClient(tr)
	if err != nil {
		return nil, errors.Wrap(err, "error building http client")
	}

	// we need to print response body before check status for debugging
	// client.CheckResponseStatus = provider.SuccessOrRedirectResponseValidator

	return &Client{
		client: client,
		mfa:    idpAccount.MFA,
	}, nil
}

// GetLoginInfo will:
// access url => get parameters from hidden fields in html
func (c *Client) GetLoginInfo() (LoginInfo, error) {

	var loginInfo LoginInfo

	loginUrl := fmt.Sprintf("https://%s", c.host)

	req, err := http.NewRequest("GET", loginUrl, nil)
	if err != nil {
		return loginInfo, errors.Wrap(err, "error building login page request")
	}

	res, err := c.client.Do(req)
	if err != nil {
		return loginInfo, errors.Wrap(err, "error retrieving login page")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return loginInfo, errors.Wrap(err, "error retrieving body from login page")
	}

	resp := string(body)
	logger.WithField("body", resp).Debug("the body from login page")

	loginInfo.Xsrf = xsrfExp.FindStringSubmatch(resp)[1]
	loginInfo.Xsrfid = xsrfidExp.FindStringSubmatch(resp)[1]
	loginInfo.Xctx = xctxExp.FindStringSubmatch(resp)[1]
	loginInfo.Xversion = xversionExp.FindStringSubmatch(resp)[1]

	logger.WithField("xsrf", loginInfo.Xsrf).
		WithField("xsrfid", loginInfo.Xsrfid).
		WithField("xctx", loginInfo.Xctx).
		WithField("xversion", loginInfo.Xversion).
		Debug("the xsrf tokens from login page")

	return loginInfo, nil
}

// DoLogin will:
// post json to /api/v1/login => get login result in json
// the json result will be ignored because 200 already indicates successfully
func (c *Client) DoLogin(loginInfo *LoginInfo, loginDetails *creds.LoginDetails) error {

	loginRequest := LoginRequest{
		Navigator: "{}",
		Username: loginDetails.Username,
		Password: loginDetails.Password,
	}
	loginRequestBuf := new(bytes.Buffer)
	err := json.NewEncoder(loginRequestBuf).Encode(loginRequest)
	if err != nil {
		return errors.Wrap(err, "error encoding loginRequest")
	}

	loginUrl := fmt.Sprintf("https://%s/api/v1/login", c.host)

	req, err := http.NewRequest("POST", loginUrl, loginRequestBuf)
	if err != nil {
		return errors.Wrap(err, "error building login request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Origin", fmt.Sprintf("https://%s", c.host))
	req.Header.Add("x-language", "english")
	req.Header.Add("x-navigator-id", c.navigatorId)
	req.Header.Add("xctx", loginInfo.Xctx)
	req.Header.Add("xsrf", loginInfo.Xsrf)
	req.Header.Add("xsrfid", loginInfo.Xsrfid)

	logger.WithField("cookie", c.client.Client.Jar).Debug("cookie jar")

	res, err := c.client.Do(req)

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return errors.Wrap(err, "error retrieving body of login result")
	}

	resp := string(body)
	logger.WithField("body", resp).Debug("the body of login result")

	if res.StatusCode == 401 {
		return errors.New("Incorrect email address or password")
	}
	if err != nil {
		return errors.Wrap(err, "error retrieving login result")
	}

	var loginResponse LoginResponse
	err = json.Unmarshal(body, &loginResponse)
	if err != nil {
		return errors.Wrap(err, "error unmarshaling json of login result")
	}
	c.requireMFABeforeListApp = loginResponse.MFA.App.Enable

	return nil
}

// GetAppInfo will:
// get app list from /api/v1/apps => choose app
func (c *Client) GetAppInfo(loginInfo *LoginInfo) (AppInfo, error) {

	var appInfo AppInfo

	getAppsUrl := fmt.Sprintf("https://%s/api/v1/apps", c.host)

	req, err := http.NewRequest("GET", getAppsUrl, nil)
	if err != nil {
		return appInfo, errors.Wrap(err, "error building get apps request")
	}

	req.Header.Add("Origin", fmt.Sprintf("https://%s", c.host))
	req.Header.Add("x-language", "english")
	req.Header.Add("x-navigator-id", c.navigatorId)
	req.Header.Add("xctx", loginInfo.Xctx)
	req.Header.Add("xsrf", loginInfo.Xsrf)
	req.Header.Add("xsrfid", loginInfo.Xsrfid)

	res, err := c.client.Do(req)

	body, bodyErr := ioutil.ReadAll(res.Body)
	resp := string(body)
	logger.WithField("body", resp).Debug("the body of get apps result")

	if err != nil {
		return appInfo, errors.Wrap(err, "error retrieving apps")
	}

	if bodyErr != nil {
		return appInfo, errors.Wrap(bodyErr, "error retrieving body of apps")
	}

	var appsResponse AppsResponse
	err = json.Unmarshal(body, &appsResponse)
	if err != nil {
		return appInfo, errors.Wrap(err, "error unmarshaling json of apps")
	}

	var appOptions []string
	for _, app := range appsResponse.Apps {
		appOptions = append(appOptions, app.Name)
	}
	if len(appOptions) == 0 {
		return appInfo, errors.New("No apps available")
	}

	var appOption = prompter.Choose("Select which app to use", appOptions)
	appInfo = appsResponse.Apps[appOption]

	return appInfo, nil
}

// DoNavigate will:
// call /api/v2/apps/navigate => get nativate url from json =>
// get navigate info from html
func (c *Client) DoNavigate(loginInfo *LoginInfo, appInfo *AppInfo) (string, error) {

	navigateRequest := NavigateRequest{Hostname: appInfo.Hostname}
	navigateRequestBuf := new(bytes.Buffer)
	err := json.NewEncoder(navigateRequestBuf).Encode(navigateRequest)
	if err != nil {
		return "", errors.Wrap(err, "error encoding navigateRequest")
	}

	navigateUrl := fmt.Sprintf("https://%s/api/v2/apps/navigate", c.host)

	req, err := http.NewRequest("POST", navigateUrl, navigateRequestBuf)
	if err != nil {
		return "", errors.Wrap(err, "error building navigate request")
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Origin", fmt.Sprintf("https://%s", c.host))
	req.Header.Add("x-language", "english")
	req.Header.Add("x-navigator-id", c.navigatorId)
	req.Header.Add("xctx", loginInfo.Xctx)
	req.Header.Add("xsrf", loginInfo.Xsrf)
	req.Header.Add("xsrfid", loginInfo.Xsrfid)

	res, err := c.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving navigate result")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving body of navigate result")
	}

	resp := string(body)
	logger.WithField("body", resp).Debug("the body of navigate result")

	var navigateResponse NavigateResponse
	err = json.Unmarshal(body, &navigateResponse)
	if err != nil {
		return "", errors.Wrap(err, "error unmarshaling json of navigate result")
	}

	if navigateResponse.Navigate.Body != "" {
		return navigateResponse.Navigate.Body, nil
	}

	navigatePageUrl := fmt.Sprintf("https://%s%s", c.host, navigateResponse.Navigate.Url)

	req, err = http.NewRequest("GET", navigatePageUrl, nil)
	if err != nil {
		return "", errors.Wrap(err, "error building navigate page request")
	}

	res, err = c.client.Do(req)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving navigate page")
	}

	body, err = ioutil.ReadAll(res.Body)
	if err != nil {
		return "", errors.Wrap(err, "error retrieving body from navigate page")
	}

	resp = string(body)
	logger.WithField("body", resp).Debug("the body from navigate page")

	loginInfo.Xsrf = xsrfExp.FindStringSubmatch(resp)[1]
	loginInfo.Xsrfid = xsrfidExp.FindStringSubmatch(resp)[1]
	loginInfo.Xctx = xctxExp.FindStringSubmatch(resp)[1]
	loginInfo.Xversion = xversionExp.FindStringSubmatch(resp)[1]

	logger.WithField("xsrf", loginInfo.Xsrf).
		WithField("xsrfid", loginInfo.Xsrfid).
		WithField("xctx", loginInfo.Xctx).
		WithField("xversion", loginInfo.Xversion).
		Debug("the xsrf tokens from navigate page (updates loginInfo)")

	return resp, nil
}

// GetMFAInfo will:
// call /api/v1/mfa/token/settings => get verify method and target from json
func (c *Client) GetMFAInfo(loginInfo *LoginInfo) (MFAInfo, error) {

	var mfaInfo MFAInfo

	getMFASettingsUrl := fmt.Sprintf("https://%s/api/v1/mfa/token/settings", c.host)

	req, err := http.NewRequest("GET", getMFASettingsUrl, nil)
	if err != nil {
		return mfaInfo, errors.Wrap(err, "error building get MFA settings request")
	}

	req.Header.Add("Origin", fmt.Sprintf("https://%s", c.host))
	req.Header.Add("x-language", "english")
	req.Header.Add("x-navigator-id", c.navigatorId)
	req.Header.Add("xctx", loginInfo.Xctx)
	req.Header.Add("xsrf", loginInfo.Xsrf)
	req.Header.Add("xsrfid", loginInfo.Xsrfid)

	res, err := c.client.Do(req)
	if err != nil {
		return mfaInfo, errors.Wrap(err, "error retrieving MFA settings")
	}

	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return mfaInfo, errors.Wrap(err, "error retrieving body from MFA settings")
	}

	resp := string(body)
	logger.WithField("body", resp).Debug("the body from get MFA settings result")

	var mfaSettingsResponse MFASettingsResponse
	err = json.Unmarshal(body, &mfaSettingsResponse)
	if err != nil {
		return mfaInfo, errors.Wrap(err, "error unmarshaling json of MFA settings")
	}

	mfaOption := strings.ToLower(c.mfa)
	if mfaOption == "auto" {
		mfaOption = mfaSettingsResponse.MFA.Settings["preferred"].
			(map[string]interface{})["option"].(string)
	}

	if mfaOption == "sms" {
		mfaInfo.Option = "phone"
		mfaInfo.UUID = mfaSettingsResponse.MFA.Settings["sms"].
			([]interface{})[0].
			(map[string]interface{})["uuid"].(string)
		mfaInfo.Target = "phone"
	} else if mfaOption == "totp" {
		mfaInfo.Option = "totp"
		mfaInfo.UUID = mfaSettingsResponse.MFA.Settings["totp"].
			([]interface{})[0].
			(map[string]interface{})["uuid"].(string)
		if mfaTarget, ok := mfaSettingsResponse.MFA.Settings["totp"].
			([]interface{})[0].
			(map[string]interface{})["value"]; ok {
			mfaInfo.Target = mfaTarget.(string)
		} else {
			mfaInfo.Target = mfaInfo.UUID
		}
	} else {
		return mfaInfo, errors.New("error unspported mfa option: " + mfaOption)
	}

	return mfaInfo, nil
}

// DoMFAVerify will:
// call /api/v1/mfa/user/{option}/token/push => sent verify code to target if not using totp =>
// ask verification code =>
// call /api/v1/mfa/user/{option}/token/verify => get json with html body which contains saml response
func (c *Client) DoMFAVerify(loginInfo *LoginInfo, mfaInfo *MFAInfo) (string, error) {

	var mfaResult string

	if mfaInfo.Option != "totp" {
		pushRequest := PushRequest{Force: false, UUID: mfaInfo.UUID}
		pushRequestBuf := new(bytes.Buffer)
		err := json.NewEncoder(pushRequestBuf).Encode(pushRequest)
		if err != nil {
			return mfaResult, errors.Wrap(err, "error encoding pushRequest")
		}

		pushUrl := fmt.Sprintf("https://%s/api/v1/mfa/user/%s/token/push", c.host, mfaInfo.Option)

		req, err := http.NewRequest("POST", pushUrl, pushRequestBuf)
		if err != nil {
			return mfaResult, errors.Wrap(err, "error building push request")
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Origin", fmt.Sprintf("https://%s", c.host))
		req.Header.Add("x-language", "english")
		req.Header.Add("x-navigator-id", c.navigatorId)
		req.Header.Add("xctx", loginInfo.Xctx)
		req.Header.Add("xsrf", loginInfo.Xsrf)
		req.Header.Add("xsrfid", loginInfo.Xsrfid)

		res, err := c.client.Do(req)
		if err != nil {
			return mfaResult, errors.Wrap(err, "error retrieving push result")
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return mfaResult, errors.Wrap(err, "error retrieving body of push result")
		}

		resp := string(body)
		logger.WithField("body", resp).Debug("the body of push result")
	}

	retryCount := 0
	for {
		// the uuid of every totp method will be google, so don't display it
		promptMsg := "Enter verification code [%s]"
		if retryCount > 0 {
			promptMsg = "Incorrect verification code, please enter again [%s]"
		}
		code := prompter.StringRequired(fmt.Sprintf(promptMsg, mfaInfo.Option))

		verifyRequest := VerifyRequest{
			Category: mfaInfo.Option,
			Token: code,
			UUID: mfaInfo.UUID,
		}
		verifyRequestBuf := new(bytes.Buffer)
		err := json.NewEncoder(verifyRequestBuf).Encode(verifyRequest)
		if err != nil {
			return mfaResult, errors.Wrap(err, "error encoding verifyRequest")
		}

		verifyUrl := fmt.Sprintf("https://%s/api/v1/mfa/user/%s/token/verify", c.host, mfaInfo.Option)

		req, err := http.NewRequest("POST", verifyUrl, verifyRequestBuf)
		if err != nil {
			return mfaResult, errors.Wrap(err, "error building verify request")
		}

		req.Header.Add("Content-Type", "application/json")
		req.Header.Add("Origin", fmt.Sprintf("https://%s", c.host))
		req.Header.Add("x-language", "english")
		req.Header.Add("x-navigator-id", c.navigatorId)
		req.Header.Add("xctx", loginInfo.Xctx)
		req.Header.Add("xsrf", loginInfo.Xsrf)
		req.Header.Add("xsrfid", loginInfo.Xsrfid)

		res, err := c.client.Do(req)
		if err != nil {
			return mfaResult, errors.Wrap(err, "error retrieving verify result")
		}

		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return mfaResult, errors.Wrap(err, "error retrieving body of verify result")
		}

		resp := string(body)
		logger.WithField("body", resp).Debug("the body of verify result")

		if res.StatusCode == 400 {
			retryCount += 1
			if retryCount >= 5 {
				return mfaResult, errors.New("Incorrect verification code")
			} else {
				continue
			}
		}

		var verifyResponse VerifyResponse
		err = json.Unmarshal(body, &verifyResponse)
		if err != nil {
			return mfaResult, errors.Wrap(err, "error unmarshaling json of verify result")
		}

		mfaResult = verifyResponse.Response.Body

		return mfaResult, nil
	}
}

// GetSAMLResponse will:
// get saml response from html body in mfa result json
func (c *Client) GetSAMLResponse(mfaResult string) (string, error) {

	matchResult := samlResponseExp.FindStringSubmatch(mfaResult)

	if matchResult == nil {
		return "", errors.New("error matching saml response in MFA result")
	}

	samlResponse := html.UnescapeString(matchResult[1])

	return samlResponse, nil
}

// Authenticate logs into EAA and returns a SAML response
func (c *Client) Authenticate(loginDetails *creds.LoginDetails) (string, error) {

	var samlAssertion string

	loginUrl, err := url.Parse(loginDetails.URL)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error building loginUrl")
	}

	c.host = loginUrl.Host

	var navigatorBytes [32]byte
	rand.Read(navigatorBytes[:])
	c.navigatorId = fmt.Sprintf("%x", sha256.Sum256(navigatorBytes[:]))

	loginInfo, err := c.GetLoginInfo()
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error getting login information")
	}

	err = c.DoLogin(&loginInfo, loginDetails)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error doing login")
	}

	mfaInfo, err := c.GetMFAInfo(&loginInfo)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error getting MFA information")
	}

	var mfaResult string

	if c.requireMFABeforeListApp {
		_, err := c.DoMFAVerify(&loginInfo, &mfaInfo)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error doing MFA verify")
		}

		appInfo, err := c.GetAppInfo(&loginInfo)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error getting app information")
		}

		mfaResult, err = c.DoNavigate(&loginInfo, &appInfo)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error doing navigate")
		}

	} else {
		appInfo, err := c.GetAppInfo(&loginInfo)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error getting app information")
		}

		_, err = c.DoNavigate(&loginInfo, &appInfo)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error doing navigate")
		}

		mfaResult, err = c.DoMFAVerify(&loginInfo, &mfaInfo)
		if err != nil {
			return samlAssertion, errors.Wrap(err, "error doing MFA verify")
		}
	}

	samlAssertion, err = c.GetSAMLResponse(mfaResult)
	if err != nil {
		return samlAssertion, errors.Wrap(err, "error getting saml response")
	}

	logger.WithField("saml", samlAssertion).Debug("the saml assertion")

	return samlAssertion, nil
}
