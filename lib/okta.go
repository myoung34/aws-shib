package lib

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/99designs/keyring"
	"github.com/CUBoulder-OIT/aws-shib/lib/saml"
	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"golang.org/x/net/publicsuffix"

	"github.com/anaskhan96/soup"
)

type SAMLAssertion struct {
	Resp    *saml.Response
	RawData []byte
}

type OktaCreds struct {
	Organization string
	Username     string
	Password     string
}

type OktaProvider struct {
	Keyring         keyring.Keyring
	ProfileARN      string
	SessionDuration time.Duration
	OktaAwsSAMLUrl  string
}

func (p *OktaProvider) Retrieve() (sts.Credentials, string, error) {
	log.Debug("using shib provider")
	var oktaCreds OktaCreds
	base, err := url.Parse(p.OktaAwsSAMLUrl)
	if err != nil {
		return sts.Credentials{}, "", errors.New("Unable to parse SAML URL")
	}
	//Check for stored session shibboleth session token
	var sessionCookie string
	cookieItem, err := p.Keyring.Get("shib-session-cookie")
	if err == nil {
		sessionCookie = string(cookieItem.Data)
	}
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return sts.Credentials{}, "", errors.New("Unable to create CookieJar")
	}

	if sessionCookie != "" {
		jar.SetCookies(base, []*http.Cookie{
			{
				Name:     "shib_idp_session",
				Value:    sessionCookie,
				Path:     "/idp",
				HttpOnly: true,
			},
		})
	}
	client := http.Client{
		Jar: jar,
	}

	if log.GetLevel().String() == "debug" {
		soup.SetDebug(true)
	}

	resp, err := soup.GetWithClient(p.OktaAwsSAMLUrl, &client)

	if err != nil {
		return sts.Credentials{}, "", errors.New("Failed to access Shibboleth URL")
	}
	log.Debug("Step: 1")
	doc := soup.HTMLParse(resp)
	soup.SetDebug(false)
	sessionInvalid := (doc.FindStrict("input", "name", "SAMLResponse").NodeValue == "")
	if log.GetLevel().String() == "debug" {
		soup.SetDebug(true)
	}
	log.Debug("Valid Session: " + strconv.FormatBool(!sessionInvalid))
	var inputs []soup.Root
	if sessionInvalid {
		//Session Token was invalid - start with authentication
		item, err := p.Keyring.Get("shib-creds")
		if err != nil {
			log.Debug("couldnt get shib creds from keyring: %s", err)
			//Prompt for username/password
			oktaCreds.Username, _ = Prompt("Identikey username", false)
			oktaCreds.Password, _ = Prompt("Identikey password", true)
			fmt.Println()
		} else {

			if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
				return sts.Credentials{}, "", errors.New("Failed to get shib credentials from your keyring.  Please make sure you have added shib credentials with `aws-okta add`")
			}
		}
		inputs := doc.FindAll("input")
		payload := url.Values{}
		for _, input := range inputs {
			var name = input.Attrs()["name"]
			var value = input.Attrs()["value"]
			if strings.Contains(strings.ToLower(name), "user") {
				payload.Add(name, oktaCreds.Username)
			} else if strings.Contains(strings.ToLower(name), "email") {
				payload.Add(name, oktaCreds.Username)
			} else if strings.Contains(strings.ToLower(name), "pass") {
				payload.Add(name, oktaCreds.Password)
			} else if strings.Contains(strings.ToLower(name), "revoke") {
				//fmt.Println("Not setting revoke attribute")
			} else {
				payload.Add(name, value)
			}
		}
		payload.Add("_eventId_proceed", "")

		formaction := doc.Find("form").Attrs()["action"]
		idpurl, err := url.Parse(p.OktaAwsSAMLUrl)
		if err != nil {
			fmt.Println(err)
		}
		var idpauthformsubmiturl = idpurl.Scheme + "://" + idpurl.Host + formaction

		var resp2, _ = http.PostForm(idpauthformsubmiturl, payload)
		defer resp2.Body.Close()
		body, err := ioutil.ReadAll(resp2.Body)
		cookies := resp2.Cookies()
		var newSessionCookie string
		for _, cookie := range cookies {
			if cookie.Name == "shib_idp_session" {
				newSessionCookie = cookie.Value
			}
		}

		//Duo challenge goes here
		log.Debug("Step: 2")
		doc = soup.HTMLParse(string(body))
		var iframe = doc.Find("iframe")
		if iframe.NodeValue != "" {
			var DuoClient = &DuoClient{
				Host:       iframe.Attrs()["data-host"],
				Signature:  iframe.Attrs()["data-sig-request"],
				Callback:   idpurl.Scheme + "://" + idpurl.Host + iframe.Attrs()["data-post-action"],
				StateToken: "",
			}
			log.Debugf("Host:%s\nSignature:%s\nCallback:%s\n",
				DuoClient.Host, DuoClient.Signature,
				DuoClient.Callback)

			log.Debug("challenge u2f")
			log.Info("Sending Push Notification...")
			var ns string
			body, ns, err = DuoClient.ChallengeU2f()
			if err != nil {
				return sts.Credentials{}, "", errors.New("Failed Duo Challenge")
			}
			if ns != "" {
				newSessionCookie = ns
			}
		}

		newCookieItem := keyring.Item{
			Key:   "shib-session-cookie",
			Data:  []byte(newSessionCookie),
			Label: "shib session cookie",
			KeychainNotTrustApplication: false,
		}

		p.Keyring.Set(newCookieItem)

		doc = soup.HTMLParse(string(body))
	} //else Session Token was valid - got a SAMLResponse so start from here

	log.Debug("Step: 3")
	var assertion = ""

	inputs = doc.FindAll("input")
	for _, input := range inputs {
		var name = input.Attrs()["name"]
		if strings.Contains(name, "SAMLResponse") {
			assertion = input.Attrs()["value"]
		}
	}
	if assertion == "" {
		return sts.Credentials{}, "", errors.New("No SAML assertion in response")
	}

	var s saml.Response
	var a, _ = base64.StdEncoding.DecodeString(assertion)
	err = xml.Unmarshal(a, &s)

	principal, role, err := GetRoleFromSAML(&s, p.ProfileARN)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	// Step 4 : Assume Role with SAML
	log.Debug("Step: 4")
	samlSess := session.Must(session.NewSession())
	svc := sts.New(samlSess)

	samlParams := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(principal),
		RoleArn:         aws.String(role),
		SAMLAssertion:   aws.String(assertion),
		DurationSeconds: aws.Int64(int64(p.SessionDuration.Seconds())),
	}

	samlResp, err := svc.AssumeRoleWithSAML(samlParams)
	if err != nil {
		log.WithField("role", role).Errorf(
			"error assuming role with SAML: %s", err.Error())
		return sts.Credentials{}, "", err
	}

	return *samlResp.Credentials, oktaCreds.Username, nil
	//return creds, oktaCreds.Username, err
}
