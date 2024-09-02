package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/nharu-0630/gakujo-zero-api/configs"
	"github.com/nharu-0630/gakujo-zero-api/tools"
)

type AuthSession struct {
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

func NewAuthSession(c Cmd, username string, password string, secret string) *AuthSession {
	return &AuthSession{
		cmd:      c,
		username: username,
		password: password,
		secret:   secret,
	}
}

func (as *AuthSession) authReq1() error {
	req, err := http.NewRequest("GET", "https://gakujo.shizuoka.ac.jp/lcu-web/", nil)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "none")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
	}
	csrf, err := extractCSRFToken(resp)
	if err != nil {
		return err
	}
	as.token = csrf
	return nil
}

func (as *AuthSession) authReq2() error {
	var data = strings.NewReader(`account=&password=&locale=ja&_csrf=` + as.token)
	req, err := http.NewRequest("POST", "https://gakujo.shizuoka.ac.jp/lcu-web/shibbolethLogin/sso?lang=ja", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://gakujo.shizuoka.ac.jp")
	req.Header.Set("DNT", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "https://gakujo.shizuoka.ac.jp/lcu-web/")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
	}
	csrf, err := extractCSRFToken(resp)
	if err != nil {
		return err
	}
	as.token = csrf
	return nil
}

func (as *AuthSession) authReq3() error {
	var data = strings.NewReader(`csrf_token=` + as.token + `&shib_idp_ls_exception.shib_idp_session_ss=&shib_idp_ls_success.shib_idp_session_ss=true&shib_idp_ls_value.shib_idp_session_ss=&shib_idp_ls_exception.shib_idp_persistent_ss=&shib_idp_ls_success.shib_idp_persistent_ss=true&shib_idp_ls_value.shib_idp_persistent_ss=&shib_idp_ls_supported=true&_eventId_proceed=`)
	req, err := http.NewRequest("POST", "https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s1", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://idp.shizuoka.ac.jp")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s1")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
	}

	re := regexp.MustCompile(`Config={(.*?)};`)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	matches := re.FindStringSubmatch(string(body))
	if len(matches) == 0 {
		return errors.New("unexpected status code")
	}
	config := matches[1]
	as.config = make(map[string]string)
	for _, line := range strings.Split(config, ",") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			log.Println("Invalid line:", line)
			continue
		}
		key := strings.Trim(parts[0], `"`+"`")
		value := strings.Trim(parts[1], `"`+"`")
		as.config[key] = value
	}

	as.referer = resp.Request.URL.String()
	return nil
}

func (as *AuthSession) authReq4() error {
	var data = strings.NewReader(`{"username":"` + as.username + `","isOtherIdpSupported":true,"checkPhones":false,"isRemoteNGCSupported":true,"isCookieBannerShown":false,"isFidoSupported":true,"originalRequest":"` + as.config["sCtx"] + `","country":"JP","forceotclogin":false,"isExternalFederationDisallowed":false,"isRemoteConnectSupported":false,"federationFlags":0,"isSignup":false,"flowToken":"` + as.config["sFT"] + `","isAccessPassSupported":true,"isQrCodePinSupported":true}`)
	req, err := http.NewRequest("POST", "https://login.microsoftonline.com/common/GetCredentialType?mkt=ja", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Referer", as.referer)
	req.Header.Set("hpgid", as.config["hpgid"])
	req.Header.Set("hpgact", as.config["hpgact"])
	req.Header.Set("canary", as.config["apiCanary"])
	req.Header.Set("client-request-id", as.config["correlationId"])
	req.Header.Set("hpgrequestid", as.config["sessionId"])
	req.Header.Set("Content-type", "application/json; charset=utf-8")
	req.Header.Set("Origin", "https://login.microsoftonline.com")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Priority", "u=0")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	req.Header.Set("TE", "trailers")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
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
	as.credential = make(map[string]string)
	for key, value := range credentialMap {
		as.credential[key] = fmt.Sprintf("%v", value)
	}
	return nil
}

func (as *AuthSession) authReq5() error {
	var data = strings.NewReader(`i13=0&login=` + url.QueryEscape(as.username) + `&loginfmt=` + url.QueryEscape(as.username) + `&type=11&LoginOptions=3&lrt=&lrtPartition=&hisRegion=&hisScaleUnit=&passwd=` + url.QueryEscape(as.password) + `&ps=2&psRNGCDefaultType=&psRNGCEntropy=&psRNGCSLK=&canary=` + url.QueryEscape(as.config["canary"]) + `&ctx=` + as.config["sCtx"] + `&hpgrequestid=` + as.config["sessionId"] + `&flowToken=` + as.credential["FlowToken"] + `&PPSX=&NewUser=1&FoundMSAs=&fspost=0&i21=0&CookieDisclosure=0&IsFidoSupported=1&isSignupPost=0&DfpArtifact=&i19=935791`)
	req, err := http.NewRequest("POST", as.config["urlPost"], data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Referer", as.referer)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://login.microsoftonline.com")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
	}

	re := regexp.MustCompile(`Config={(.*?)};`)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	matches := re.FindStringSubmatch(string(body))
	if len(matches) == 0 {
		return errors.New("config not found")
	}
	config := matches[1]
	as.config = make(map[string]string)
	for _, line := range strings.Split(config, ",") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			log.Println("Invalid line:", line)
			continue
		}
		key := strings.Trim(parts[0], `"`+"`")
		value := strings.Trim(parts[1], `"`+"`")
		as.config[key] = value
	}

	return nil
}

func (as *AuthSession) authReq6() error {
	var data = strings.NewReader(`{"AuthMethodId":"PhoneAppOTP","Method":"BeginAuth","ctx":"` + as.config["sCtx"] + `","flowToken":"` + as.config["sFT"] + `"}`)
	req, err := http.NewRequest("POST", "https://login.microsoftonline.com/common/SAS/BeginAuth", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Referer", strings.Replace(as.config["urlLogout"], "uxlogout", "login", 1))
	req.Header.Set("hpgid", as.config["hpgid"])
	req.Header.Set("hpgact", as.config["hpgact"])
	req.Header.Set("canary", as.config["apiCanary"])
	req.Header.Set("client-request-id", as.config["correlationId"])
	req.Header.Set("hpgrequestid", as.config["sessionId"])
	req.Header.Set("Content-type", "application/json; charset=utf-8")
	req.Header.Set("Origin", "https://login.microsoftonline.com")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
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
	as.begin = make(map[string]string)
	for key, value := range beginData {
		as.begin[key] = fmt.Sprintf("%v", value)
	}
	return nil
}

func (as *AuthSession) authReq7() error {
	as.timestamp = time.Now().Unix()
	as.otp = strings.TrimSpace(fmt.Sprintf("%06d", tools.TOTP(as.secret, 30)))
	var data = strings.NewReader(`{"Method":"EndAuth","SessionId":"` + as.begin["SessionId"] + `","FlowToken":"` + as.begin["FlowToken"] + `","Ctx":"` + as.config["sCtx"] + `","AuthMethodId":"PhoneAppOTP","AdditionalAuthData":"` + as.otp + `","PollCount":1}`)
	req, err := http.NewRequest("POST", "https://login.microsoftonline.com/common/SAS/EndAuth", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Referer", strings.Replace(as.config["urlLogout"], "uxlogout", "login", 1))
	req.Header.Set("hpgid", as.config["hpgid"])
	req.Header.Set("hpgact", as.config["hpgact"])
	req.Header.Set("canary", as.config["apiCanary"])
	req.Header.Set("client-request-id", as.config["correlationId"])
	req.Header.Set("hpgrequestid", as.config["sessionId"])
	req.Header.Set("Content-type", "application/json; charset=utf-8")
	req.Header.Set("Origin", "https://login.microsoftonline.com")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Sec-Fetch-Dest", "empty")
	req.Header.Set("Sec-Fetch-Mode", "cors")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Priority", "u=0")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Default().Println("Response Body:", string(body))

	var endData map[string]interface{}
	err = json.Unmarshal(body, &endData)
	if err != nil {
		return err
	}
	as.end = make(map[string]string)
	for key, value := range endData {
		as.end[key] = fmt.Sprintf("%v", value)
	}
	return nil
}

func (as *AuthSession) authReq8() error {
	var data = strings.NewReader(`type=19&GeneralVerify=false&request=` + as.end["Ctx"] + `&mfaLastPollStart=` + strconv.FormatInt(as.timestamp-10000, 10) + `&mfaLastPollEnd=` + strconv.FormatInt(as.timestamp+10000, 10) + `&mfaAuthMethod=PhoneAppOTP&otc=` + as.otp + `&login=` + url.QueryEscape(as.username) + `&flowToken=` + as.end["FlowToken"] + `&hpgrequestid=` + as.config["sessionId"] + `&sacxt=&hideSmsInMfaProofs=false&canary=` + url.QueryEscape(as.config["canary"]) + `&i19=16034`)
	req, err := http.NewRequest("POST", "https://login.microsoftonline.com/common/SAS/ProcessAuth", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Referer", strings.Replace(as.config["urlLogout"], "uxlogout", "login", 1))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://login.microsoftonline.com")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
	}

	re := regexp.MustCompile(`Config={(.*?)};`)
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}

	matches := re.FindStringSubmatch(string(body))
	if len(matches) == 0 {
		return errors.New("config not found")
	}
	config := matches[1]
	as.config = make(map[string]string)
	for _, line := range strings.Split(config, ",") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) != 2 {
			log.Println("Invalid line:", line)
			continue
		}
		key := strings.Trim(parts[0], `"`+"`")
		value := strings.Trim(parts[1], `"`+"`")
		as.config[key] = value
	}
	return nil
}

func (as *AuthSession) authReq9() error {
	var data = strings.NewReader(`LoginOptions=1&type=28&ctx=` + as.config["sCtx"] + `&hpgrequestid=` + as.config["sessionId"] + `&flowToken=` + as.config["sFT"] + `&DontShowAgain=true&canary=` + url.QueryEscape(as.config["canary"]) + `&i19=3975`)
	req, err := http.NewRequest("POST", "https://login.microsoftonline.com/kmsi", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Referer", "https://login.microsoftonline.com/common/SAS/ProcessAuth")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://login.microsoftonline.com")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	re := regexp.MustCompile(`<input type="hidden" name="SAMLResponse" value="([^"]+)"`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) == 0 {
		return errors.New("SAMLResponse not found")
	}
	as.samlReq = matches[1]
	return nil
}

func (as *AuthSession) authReq10() error {
	var data = strings.NewReader(`SAMLResponse=` + url.QueryEscape(as.samlReq) + `&RelayState=e1s2`)
	req, err := http.NewRequest("POST", "https://idp.shizuoka.ac.jp/idp/profile/Authn/SAML2/POST/SSO", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Referer", "https://login.microsoftonline.com/")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://login.microsoftonline.com")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "cross-site")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
	}
	csrf, err := extractCSRFToken(resp)
	if err != nil {
		return err
	}
	as.token = csrf
	return nil
}

func (as *AuthSession) authReq11() error {
	var data = strings.NewReader(`csrf_token=` + as.token + `&_shib_idp_consentIds=displayName&_shib_idp_consentIds=eduPersonAffiliation&_shib_idp_consentIds=eduPersonEntitlement&_shib_idp_consentIds=eduPersonPrincipalName&_shib_idp_consentIds=eduPersonScopedAffiliation&_shib_idp_consentIds=eduPersonTargetedID&_shib_idp_consentIds=employeeNumber&_shib_idp_consentIds=givenName&_shib_idp_consentIds=jaDisplayName&_shib_idp_consentIds=jaGivenName&_shib_idp_consentIds=jaOrganizationName&_shib_idp_consentIds=jaSurname&_shib_idp_consentIds=jaorganizationalUnit&_shib_idp_consentIds=mail&_shib_idp_consentIds=organizationName&_shib_idp_consentIds=organizationalUnitName&_shib_idp_consentIds=surname&_shib_idp_consentIds=uid&_shib_idp_consentOptions=_shib_idp_rememberConsent&_eventId_proceed=`)
	req, err := http.NewRequest("POST", "https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s3", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://idp.shizuoka.ac.jp")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s3")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Sec-Fetch-User", "?1")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
	}
	csrf, err := extractCSRFToken(resp)
	if err != nil {
		return err
	}
	as.token = csrf
	return nil
}

func (as *AuthSession) authReq12() error {
	var data = strings.NewReader(`csrf_token=` + as.token + `&shib_idp_ls_exception.shib_idp_session_ss=&shib_idp_ls_success.shib_idp_session_ss=true&shib_idp_ls_exception.shib_idp_persistent_ss=&shib_idp_ls_success.shib_idp_persistent_ss=true&_eventId_proceed=`)
	req, err := http.NewRequest("POST", "https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s4", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://idp.shizuoka.ac.jp")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "https://idp.shizuoka.ac.jp/idp/profile/SAML2/Redirect/SSO?execution=e1s4")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	resp.Body = io.NopCloser(strings.NewReader(string(body)))
	re := regexp.MustCompile(`<input type="hidden" name="RelayState" value="([^"]+)"`)
	matches := re.FindStringSubmatch(string(body))
	if len(matches) == 0 {
		return errors.New("RelayState not found")
	}
	as.relayState = matches[1]
	re = regexp.MustCompile(`<input type="hidden" name="SAMLResponse" value="([^"]+)"`)
	matches = re.FindStringSubmatch(string(body))
	if len(matches) == 0 {
		return errors.New("SAMLResponse not found")
	}
	as.samlRes = matches[1]
	return nil
}

func (as *AuthSession) authReq13() error {
	var data = strings.NewReader(`RelayState=` + strings.ReplaceAll(as.relayState, "&#x3a;", "%3A") + `&SAMLResponse=` + url.QueryEscape(as.samlRes))
	req, err := http.NewRequest("POST", "https://gakujo.shizuoka.ac.jp/Shibboleth.sso/SAML2/POST", data)
	if err != nil {
		log.Fatal(err)
	}
	req.Header.Set("User-Agent", configs.USER_AGENT)
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/png,image/svg+xml,*/*;q=0.8")
	req.Header.Set("Accept-Language", "ja,en-US;q=0.7,en;q=0.3")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "https://idp.shizuoka.ac.jp")
	req.Header.Set("DNT", "1")
	req.Header.Set("Sec-GPC", "1")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Referer", "https://idp.shizuoka.ac.jp/")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	req.Header.Set("Sec-Fetch-Dest", "document")
	req.Header.Set("Sec-Fetch-Mode", "navigate")
	req.Header.Set("Sec-Fetch-Site", "same-site")
	req.Header.Set("Priority", "u=0, i")
	req.Header.Set("Pragma", "no-cache")
	req.Header.Set("Cache-Control", "no-cache")
	resp, err := as.cmd.client.Do(req)
	if err != nil {
		log.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return errors.New("unexpected status code")
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return err
	}
	log.Default().Println("Response Body:", string(body))

	return nil
}

func (as *AuthSession) Auth() error {
	err := as.authReq1()
	if err != nil {
		return err
	}
	err = as.authReq2()
	if err != nil {
		return err
	}
	err = as.authReq3()
	if err != nil {
		return err
	}
	err = as.authReq4()
	if err != nil {
		return err
	}
	err = as.authReq5()
	if err != nil {
		return err
	}
	err = as.authReq6()
	if err != nil {
		return err
	}
	err = as.authReq7()
	if err != nil {
		return err
	}
	err = as.authReq8()
	if err != nil {
		return err
	}
	err = as.authReq9()
	if err != nil {
		return err
	}
	err = as.authReq10()
	if err != nil {
		return err
	}
	err = as.authReq11()
	if err != nil {
		return err
	}
	err = as.authReq12()
	if err != nil {
		return err
	}
	err = as.authReq13()
	if err != nil {
		return err
	}
	return nil
}
