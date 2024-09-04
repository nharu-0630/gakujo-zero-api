package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/nharu-0630/gakujo-zero-api/configs"
	"github.com/nharu-0630/gakujo-zero-api/tools"
)

type LoginSession struct {
	cmd        Cmd
	username   string
	password   string
	secret     string
	token      string
	config     map[string]string
	referer    string
	credential map[string]string
	begin      map[string]string
	end        map[string]string
	timestamp  int64
	otp        string
	samlReq    string
	relayState string
	samlRes    string
}

func NewLoginSession(c Cmd, username string, password string, secret string) *LoginSession {
	return &LoginSession{
		cmd:      c,
		username: username,
		password: password,
		secret:   secret,
	}
}

func (ls *LoginSession) req1() error {
	headers := map[string]string{
		"User-Agent":                configs.USER_AGENT,
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
		"Accept-Language":           "ja,en-US;q=0.7,en;q=0.3",
		"DNT":                       "1",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "none",
		"Sec-Fetch-User":            "?1",
		"Priority":                  "u=0, i",
		"Pragma":                    "no-cache",
		"Cache-Control":             "no-cache",
	}
	resp, err := ls.cmd.request("GET", "https://gakujo.shizuoka.ac.jp/lcu-web/", nil, headers)
	if err != nil {
		return err
	}
	csrf, err := extractCSRFToken(resp)
	if err != nil {
		return err
	}
	ls.token = csrf
	return nil
}

func (ls *LoginSession) req2() error {
	data := strings.NewReader(`account=&password=&locale=ja&_csrf=` + ls.token)
	headers := map[string]string{
		"User-Agent":                configs.USER_AGENT,
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
		"Accept-Language":           "ja,en-US;q=0.7,en;q=0.3",
		"Content-Type":              "application/x-www-form-urlencoded",
		"Origin":                    "https://gakujo.shizuoka.ac.jp",
		"DNT":                       "1",
		"Connection":                "keep-alive",
		"Referer":                   "https://gakujo.shizuoka.ac.jp/lcu-web/",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-origin",
		"Sec-Fetch-User":            "?1",
		"Priority":                  "u=0, i",
		"Pragma":                    "no-cache",
		"Cache-Control":             "no-cache",
	}
	resp, err := ls.cmd.request("POST", "https://gakujo.shizuoka.ac.jp/lcu-web/shibbolethLogin/sso?lang=ja", data, headers)
	if err != nil {
		return err
	}
	csrf, err := extractCSRFToken(resp)
	if err != nil {
		return err
	}
	ls.token = csrf
	return nil
}

func (ls *LoginSession) req3() error {
	data := strings.NewReader(`csrf_token=` + ls.token + `&shib_idp_ls_exception.shib_idp_session_ss=&shib_idp_ls_success.shib_idp_session_ss=true&shib_idp_ls_value.shib_idp_session_ss=&shib_idp_ls_exception.shib_idp_persistent_ss=&shib_idp_ls_success.shib_idp_persistent_ss=true&shib_idp_ls_value.shib_idp_persistent_ss=&shib_idp_ls_supported=true&_eventId_proceed=`)
	headers := map[string]string{
		"User-Agent":                configs.USER_AGENT,
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
		"Accept-Language":           "ja,en-US;q=0.7,en;q=0.3",
		"Content-Type":              "application/x-www-form-urlencoded",
		"Origin":                    "https://idp.shizuoka.ac.jp",
		"DNT":                       "1",
		"Sec-GPC":                   "1",
		"Connection":                "keep-alive",
		"Referer":                   "https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s1",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-origin",
		"Priority":                  "u=0, i",
		"Pragma":                    "no-cache",
		"Cache-Control":             "no-cache",
	}
	resp, err := ls.cmd.request("POST", "https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s1", data, headers)
	if err != nil {
		return err
	}
	config, err := extractConfig(resp)
	if err != nil {
		return err
	}
	ls.config = config
	ls.referer = resp.Request.URL.String()
	return nil
}

func (ls *LoginSession) req4() error {
	data := strings.NewReader(`{"username":"` + ls.username + `","isOtherIdpSupported":true,"checkPhones":false,"isRemoteNGCSupported":true,"isCookieBannerShown":false,"isFidoSupported":true,"originalRequest":"` + ls.config["sCtx"] + `","country":"JP","forceotclogin":false,"isExternalFederationDisallowed":false,"isRemoteConnectSupported":false,"federationFlags":0,"isSignup":false,"flowToken":"` + ls.config["sFT"] + `","isAccessPassSupported":true,"isQrCodePinSupported":true}`)
	headers := map[string]string{
		"User-Agent":        configs.USER_AGENT,
		"Accept":            "application/json",
		"Accept-Language":   "ja,en-US;q=0.7,en;q=0.3",
		"Referer":           ls.referer,
		"hpgid":             ls.config["hpgid"],
		"hpgact":            ls.config["hpgact"],
		"canary":            ls.config["apiCanary"],
		"client-request-id": ls.config["correlationId"],
		"hpgrequestid":      ls.config["sessionId"],
		"Content-type":      "application/json; charset=utf-8",
		"Origin":            "https://login.microsoftonline.com",
		"DNT":               "1",
		"Sec-GPC":           "1",
		"Connection":        "keep-alive",
		"Sec-Fetch-Dest":    "empty",
		"Sec-Fetch-Mode":    "cors",
		"Sec-Fetch-Site":    "same-origin",
		"Priority":          "u=0",
		"Pragma":            "no-cache",
		"Cache-Control":     "no-cache",
		"TE":                "trailers",
	}
	resp, err := ls.cmd.request("POST", "https://login.microsoftonline.com/common/GetCredentialType?mkt=ja", data, headers)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var credentialMap map[string]interface{}
	err = json.Unmarshal(body, &credentialMap)
	if err != nil {
		return err
	}
	ls.credential = make(map[string]string)
	for key, value := range credentialMap {
		ls.credential[key] = fmt.Sprintf("%v", value)
	}
	return nil
}

func (ls *LoginSession) req5() error {
	data := strings.NewReader(`i13=0&login=` + url.QueryEscape(ls.username) + `&loginfmt=` + url.QueryEscape(ls.username) + `&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd=` + url.QueryEscape(ls.password) + `&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=` + url.QueryEscape(ls.config["canary"]) + `&ctx=` + ls.config["sCtx"] + `&hpgrequestid=` + ls.config["sessionId"] + `&flowToken=` + ls.credential["FlowToken"] + `&PPSX=&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&DfpArtifact=&i19=935791`)
	url := ls.config["urlPost"]
	if strings.HasPrefix(url, "/") {
		url = "https://login.microsoftonline.com" + url
	}
	headers := map[string]string{
		"User-Agent":                configs.USER_AGENT,
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
		"Accept-Language":           "ja,en-US;q=0.7,en;q=0.3",
		"Referer":                   ls.referer,
		"Content-Type":              "application/x-www-form-urlencoded",
		"Origin":                    "https://login.microsoftonline.com",
		"DNT":                       "1",
		"Sec-GPC":                   "1",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-origin",
		"Sec-Fetch-User":            "?1",
		"Priority":                  "u=0, i",
		"Pragma":                    "no-cache",
		"Cache-Control":             "no-cache",
	}
	resp, err := ls.cmd.request("POST", url, data, headers)
	if err != nil {
		return err
	}
	config, err := extractConfig(resp)
	if err != nil {
		return err
	}
	ls.config = config
	return nil
}

func (ls *LoginSession) req6() error {
	data := strings.NewReader(`{"AuthMethodId":"PhoneAppOTP","Method":"BeginAuth","ctx":"` + ls.config["sCtx"] + `","flowToken":"` + ls.config["sFT"] + `"}`)
	headers := map[string]string{
		"User-Agent":        configs.USER_AGENT,
		"Accept":            "application/json",
		"Accept-Language":   "ja,en-US;q=0.7,en;q=0.3",
		"Referer":           strings.Replace(ls.config["urlLogout"], "uxlogout", "login", 1),
		"hpgid":             ls.config["hpgid"],
		"hpgact":            ls.config["hpgact"],
		"canary":            ls.config["apiCanary"],
		"client-request-id": ls.config["correlationId"],
		"hpgrequestid":      ls.config["sessionId"],
		"Content-type":      "application/json; charset=utf-8",
		"Origin":            "https://login.microsoftonline.com",
		"DNT":               "1",
		"Sec-GPC":           "1",
		"Connection":        "keep-alive",
		"Sec-Fetch-Dest":    "empty",
		"Sec-Fetch-Mode":    "cors",
		"Sec-Fetch-Site":    "same-origin",
		"Pragma":            "no-cache",
		"Cache-Control":     "no-cache",
	}
	resp, err := ls.cmd.request("POST", "https://login.microsoftonline.com/common/SAS/BeginAuth", data, headers)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var beginData map[string]interface{}
	err = json.Unmarshal(body, &beginData)
	if err != nil {
		return err
	}
	ls.begin = make(map[string]string)
	for key, value := range beginData {
		ls.begin[key] = fmt.Sprintf("%v", value)
	}
	return nil
}

func (ls *LoginSession) req7() error {
	ls.timestamp = time.Now().Unix()
	ls.otp = strings.TrimSpace(fmt.Sprintf("%06d", tools.TOTP(ls.secret, 30)))
	data := strings.NewReader(`{"Method":"EndAuth","SessionId":"` + ls.begin["SessionId"] + `","FlowToken":"` + ls.begin["FlowToken"] + `","Ctx":"` + ls.config["sCtx"] + `","AuthMethodId":"PhoneAppOTP","AdditionalAuthData":"` + ls.otp + `","PollCount":1}`)
	headers := map[string]string{
		"User-Agent":        configs.USER_AGENT,
		"Accept":            "application/json",
		"Accept-Language":   "ja,en-US;q=0.7,en;q=0.3",
		"Referer":           strings.Replace(ls.config["urlLogout"], "uxlogout", "login", 1),
		"hpgid":             ls.config["hpgid"],
		"hpgact":            ls.config["hpgact"],
		"canary":            ls.config["apiCanary"],
		"client-request-id": ls.config["correlationId"],
		"hpgrequestid":      ls.config["sessionId"],
		"Content-type":      "application/json; charset=utf-8",
		"Origin":            "https://login.microsoftonline.com",
		"DNT":               "1",
		"Sec-GPC":           "1",
		"Connection":        "keep-alive",
		"Sec-Fetch-Dest":    "empty",
		"Sec-Fetch-Mode":    "cors",
		"Sec-Fetch-Site":    "same-origin",
		"Priority":          "u=0",
		"Pragma":            "no-cache",
		"Cache-Control":     "no-cache",
	}
	resp, err := ls.cmd.request("POST", "https://login.microsoftonline.com/common/SAS/EndAuth", data, headers)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	var endData map[string]interface{}
	err = json.Unmarshal(body, &endData)
	if err != nil {
		return err
	}
	ls.end = make(map[string]string)
	for key, value := range endData {
		ls.end[key] = fmt.Sprintf("%v", value)
	}
	return nil
}

func (ls *LoginSession) req8() error {
	data := strings.NewReader(`type=19&GeneralVerify=false&request=` + ls.end["Ctx"] + `&mfaLastPollStart=` + strconv.FormatInt(ls.timestamp-10000, 10) + `&mfaLastPollEnd=` + strconv.FormatInt(ls.timestamp+10000, 10) + `&mfaAuthMethod=PhoneAppOTP&otc=` + ls.otp + `&login=` + url.QueryEscape(ls.username) + `&flowToken=` + ls.end["FlowToken"] + `&hpgrequestid=` + ls.config["sessionId"] + `&sacxt=&hideSmsInMfaProofs=false&canary=` + url.QueryEscape(ls.config["canary"]) + `&i19=16034`)
	headers := map[string]string{
		"User-Agent":                configs.USER_AGENT,
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
		"Accept-Language":           "ja,en-US;q=0.7,en;q=0.3",
		"Referer":                   strings.Replace(ls.config["urlLogout"], "uxlogout", "login", 1),
		"Content-Type":              "application/x-www-form-urlencoded",
		"Origin":                    "https://login.microsoftonline.com",
		"DNT":                       "1",
		"Sec-GPC":                   "1",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-origin",
		"Sec-Fetch-User":            "?1",
		"Priority":                  "u=0, i",
		"Pragma":                    "no-cache",
		"Cache-Control":             "no-cache",
	}
	resp, err := ls.cmd.request("POST", "https://login.microsoftonline.com/common/SAS/ProcessAuth", data, headers)
	if err != nil {
		return err
	}
	config, err := extractConfig(resp)
	if err != nil {
		return err
	}
	ls.config = config
	return nil
}

func (ls *LoginSession) req9() error {
	data := strings.NewReader(`LoginOptions=1&type=28&ctx=` + ls.config["sCtx"] + `&hpgrequestid=` + ls.config["sessionId"] + `&flowToken=` + ls.config["sFT"] + `&DontShowAgain=true&canary=` + url.QueryEscape(ls.config["canary"]) + `&i19=3975`)
	headers := map[string]string{
		"User-Agent":                configs.USER_AGENT,
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
		"Accept-Language":           "ja,en-US;q=0.7,en;q=0.3",
		"Referer":                   "https://login.microsoftonline.com/common/SAS/ProcessAuth",
		"Content-Type":              "application/x-www-form-urlencoded",
		"Origin":                    "https://login.microsoftonline.com",
		"DNT":                       "1",
		"Sec-GPC":                   "1",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-origin",
		"Sec-Fetch-User":            "?1",
		"Priority":                  "u=0, i",
		"Pragma":                    "no-cache",
		"Cache-Control":             "no-cache",
	}
	resp, err := ls.cmd.request("POST", "https://login.microsoftonline.com/kmsi", data, headers)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	re := regexp.MustCompile(`<input type="hidden" name="SAMLResponse" value="([^"]+)"`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) == 0 {
		return errors.New("failed to extract SAMLResponse")
	}
	ls.samlReq = matches[1]
	return nil
}

func (ls *LoginSession) req10() error {
	data := strings.NewReader(`SAMLResponse=` + url.QueryEscape(ls.samlReq) + `&RelayState=e1s2`)
	headers := map[string]string{
		"User-Agent":                configs.USER_AGENT,
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
		"Accept-Language":           "ja,en-US;q=0.7,en;q=0.3",
		"Referer":                   "https://login.microsoftonline.com/",
		"Content-Type":              "application/x-www-form-urlencoded",
		"Origin":                    "https://login.microsoftonline.com",
		"DNT":                       "1",
		"Sec-GPC":                   "1",
		"Connection":                "keep-alive",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "cross-site",
		"Priority":                  "u=0, i",
		"Pragma":                    "no-cache",
		"Cache-Control":             "no-cache",
	}
	resp, err := ls.cmd.request("POST", "https://idp.shizuoka.ac.jp/idp/profile/Authn/SAML2/POST/SSO", data, headers)
	if err != nil {
		return err
	}
	csrf, err := extractCSRFToken(resp)
	if err != nil {
		return err
	}
	ls.token = csrf
	return nil
}

func (ls *LoginSession) req11() error {
	data := strings.NewReader(`csrf_token=` + ls.token + `&_shib_idp_consentIds=displayName&_shib_idp_consentIds=eduPersonAffiliation&_shib_idp_consentIds=eduPersonEntitlement&_shib_idp_consentIds=eduPersonPrincipalName&_shib_idp_consentIds=eduPersonScopedAffiliation&_shib_idp_consentIds=eduPersonTargetedID&_shib_idp_consentIds=employeeNumber&_shib_idp_consentIds=givenName&_shib_idp_consentIds=jaDisplayName&_shib_idp_consentIds=jaGivenName&_shib_idp_consentIds=jaOrganizationName&_shib_idp_consentIds=jaSurname&_shib_idp_consentIds=jaorganizationalUnit&_shib_idp_consentIds=mail&_shib_idp_consentIds=organizationName&_shib_idp_consentIds=organizationalUnitName&_shib_idp_consentIds=surname&_shib_idp_consentIds=uid&_shib_idp_consentOptions=_shib_idp_rememberConsent&_eventId_proceed=`)
	headers := map[string]string{
		"User-Agent":                configs.USER_AGENT,
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
		"Accept-Language":           "ja,en-US;q=0.7,en;q=0.3",
		"Content-Type":              "application/x-www-form-urlencoded",
		"Origin":                    "https://idp.shizuoka.ac.jp",
		"DNT":                       "1",
		"Sec-GPC":                   "1",
		"Connection":                "keep-alive",
		"Referer":                   "https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s3",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-origin",
		"Sec-Fetch-User":            "?1",
		"Priority":                  "u=0, i",
		"Pragma":                    "no-cache",
		"Cache-Control":             "no-cache",
	}
	resp, err := ls.cmd.request("POST", "https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s3", data, headers)
	if err != nil {
		return err
	}
	csrf, err := extractCSRFToken(resp)
	if err != nil {
		return err
	}
	ls.token = csrf
	return nil
}

func (ls *LoginSession) req12() error {
	data := strings.NewReader(`csrf_token=` + ls.token + `&shib_idp_ls_exception.shib_idp_session_ss=&shib_idp_ls_success.shib_idp_session_ss=true&shib_idp_ls_exception.shib_idp_persistent_ss=&shib_idp_ls_success.shib_idp_persistent_ss=true&_eventId_proceed=`)
	headers := map[string]string{
		"User-Agent":                configs.USER_AGENT,
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
		"Accept-Language":           "ja,en-US;q=0.7,en;q=0.3",
		"Content-Type":              "application/x-www-form-urlencoded",
		"Origin":                    "https://idp.shizuoka.ac.jp",
		"DNT":                       "1",
		"Sec-GPC":                   "1",
		"Connection":                "keep-alive",
		"Referer":                   "https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s4",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-origin",
		"Priority":                  "u=0, i",
		"Pragma":                    "no-cache",
		"Cache-Control":             "no-cache",
	}
	resp, err := ls.cmd.request("POST", "https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s4", data, headers)
	if err != nil {
		return err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	re := regexp.MustCompile(`<input type="hidden" name="RelayState" value="([^"]+)"`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) == 0 {
		return errors.New("failed to extract RelayState")
	}
	ls.relayState = matches[1]
	re = regexp.MustCompile(`<input type="hidden" name="SAMLResponse" value="([^"]+)"`)
	matches = re.FindStringSubmatch(string(body))
	if len(matches) == 0 {
		return errors.New("failed to extract SAMLResponse")
	}
	ls.samlRes = matches[1]
	return nil
}

func (ls *LoginSession) req13() (string, error) {
	data := strings.NewReader(`RelayState=` + strings.ReplaceAll(ls.relayState, "&#x3a;", "%3A") + `&SAMLResponse=` + url.QueryEscape(ls.samlRes))
	headers := map[string]string{
		"User-Agent":                configs.USER_AGENT,
		"Accept":                    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8",
		"Accept-Language":           "ja,en-US;q=0.7,en;q=0.3",
		"Content-Type":              "application/x-www-form-urlencoded",
		"Origin":                    "https://idp.shizuoka.ac.jp",
		"DNT":                       "1",
		"Sec-GPC":                   "1",
		"Connection":                "keep-alive",
		"Referer":                   "https://idp.shizuoka.ac.jp/",
		"Upgrade-Insecure-Requests": "1",
		"Sec-Fetch-Dest":            "document",
		"Sec-Fetch-Mode":            "navigate",
		"Sec-Fetch-Site":            "same-site",
		"Priority":                  "u=0, i",
		"Pragma":                    "no-cache",
		"Cache-Control":             "no-cache",
	}
	resp, err := ls.cmd.request("POST", "https://gakujo.shizuoka.ac.jp/Shibboleth.sso/SAML2/POST", data, headers)
	if err != nil {
		return "", err
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	if strings.Contains(string(body), "前回ログイン") {
		doc, err := goquery.NewDocumentFromReader(strings.NewReader(string(body)))
		if err != nil {
			return "", err
		}
		name := strings.Trim(doc.Find(".c-header-user-menu-name").Text(), " \n")
		return name, nil
	}
	return "", errors.New("unexpected response")
}

func (ls *LoginSession) InitLogin() error {
	err := ls.req1()
	if err != nil {
		return err
	}
	err = ls.req2()
	if err != nil {
		return err
	}
	err = ls.req3()
	if err != nil {
		return err
	}
	err = ls.req4()
	if err != nil {
		return err
	}
	err = ls.req5()
	if err != nil {
		return err
	}
	err = ls.req6()
	if err != nil {
		return err
	}
	err = ls.req7()
	if err != nil {
		return err
	}
	err = ls.req8()
	if err != nil {
		return err
	}
	err = ls.req9()
	if err != nil {
		return err
	}
	err = ls.req10()
	if err != nil {
		return err
	}
	err = ls.req11()
	if err != nil {
		return err
	}
	err = ls.req12()
	if err != nil {
		return err
	}
	return nil
}

func (c *Cmd) Login(username string, password string, secret string) (string, error) {
	ls := NewLoginSession(*c, username, password, secret)
	err := ls.InitLogin()
	if err != nil {
		return "", err
	}
	name, err := ls.req13()
	if err != nil {
		return "", err
	}
	return name, nil
}
