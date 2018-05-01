package lib

import (
	"bytes"
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
  "encoding/base64"
	"golang.org/x/net/publicsuffix"

	"github.com/99designs/keyring"
	log "github.com/Sirupsen/logrus"
	"github.com/aws/aws-sdk-go/aws"
	"github.com/aws/aws-sdk-go/aws/session"
	"github.com/aws/aws-sdk-go/service/sts"
	"github.com/segmentio/aws-okta/lib/saml"

	"github.com/anaskhan96/soup"
)

const (
	OktaServer = "okta.com"
  // region: The default AWS region that this script will connect
  // to for all API calls
  region = "us-west-2"

  // output format: The AWS CLI output format that will be configured in the
  // saml profile (affects subsequent CLI calls)
  outputformat = "json"

  // awsconfigfile: The file where this script will store the temp
  // credentials under the saml profile
  awsconfigfile = "/.aws/credentials"

  // SSL certificate verification: Whether or not strict certificate
  // verification is done, False should only be used for dev/test
  sslverification = true

  // idpentryurl: The initial url that starts the authentication process.
  idpentryurl = "https://***REMOVED***/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices"
)

type OktaClient struct {
	Organization    string
	Username        string
	Password        string
	UserAuth        *OktaUserAuthn
	DuoClient       *DuoClient
	AccessKeyId     string
	SecretAccessKey string
	SessionToken    string
	Expiration      time.Time
	OktaAwsSAMLUrl  string
	CookieJar       http.CookieJar
	BaseURL         *url.URL
}

type SAMLAssertion struct {
	Resp    *saml.Response
	RawData []byte
}

type OktaCreds struct {
	Organization string
	Username     string
	Password     string
}

func NewOktaClient(creds OktaCreds, oktaAwsSAMLUrl string, sessionCookie string) (*OktaClient, error) {
	base, err := url.Parse(fmt.Sprintf(
		"https://%s.%s", creds.Organization, OktaServer,
	))
	if err != nil {
		return nil, err
	}

	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		return nil, err
	}

	if sessionCookie != "" {
		jar.SetCookies(base, []*http.Cookie{
			{
				Name:  "sid",
				Value: sessionCookie,
			},
		})
	}

	return &OktaClient{
		Organization:   creds.Organization,
		Username:       creds.Username,
		Password:       creds.Password,
		OktaAwsSAMLUrl: oktaAwsSAMLUrl,
		CookieJar:      jar,
		BaseURL:        base,
	}, nil
}

func (o *OktaClient) AuthenticateProfile(profileARN string, duration time.Duration) (sts.Credentials, string, error) {
	var oktaUserAuthn OktaUserAuthn

	// Attempt to reuse session cookie
	var assertion SAMLAssertion
	err := o.Get("GET", o.OktaAwsSAMLUrl, nil, &assertion, "saml")
	if err != nil {
		log.Debug("Failed to reuse session token, starting flow from start")
		// Step 1 : Basic authentication
		user := OktaUser{
			Username: o.Username,
			Password: o.Password,
		}

		payload, err := json.Marshal(user)
		if err != nil {
			return sts.Credentials{}, "", err
		}

		log.Debug("Step: 1")
		err = o.Get("POST", "api/v1/authn", payload, &oktaUserAuthn, "json")
		if err != nil {
			return sts.Credentials{}, "", errors.New("Failed to authenticate with okta.  Please check that your credentials have been set correctly with `aws-okta add`")
		}

		o.UserAuth = &oktaUserAuthn

		// Step 2 : Challenge MFA if needed
		log.Debug("Step: 2")
		if o.UserAuth.Status == "MFA_REQUIRED" {
			log.Info("Requesting MFA")
			if err = o.challengeMFA(); err != nil {
				return sts.Credentials{}, "", err
			}
		}

		if o.UserAuth.SessionToken == "" {
			return sts.Credentials{}, "", fmt.Errorf("authentication failed for %s", o.Username)
		}

		// Step 3 : Get SAML Assertion and retrieve IAM Roles
		log.Debug("Step: 3")
		if err = o.Get("GET", o.OktaAwsSAMLUrl+"?onetimetoken="+o.UserAuth.SessionToken,
			nil, &assertion, "saml"); err != nil {
			return sts.Credentials{}, "", err
		}
	}

	principal, role, err := GetRoleFromSAML(assertion.Resp, profileARN)
	if err != nil {
		return sts.Credentials{}, "", err
	}

	// Step 4 : Assume Role with SAML
	samlSess := session.Must(session.NewSession())
	svc := sts.New(samlSess)

	samlParams := &sts.AssumeRoleWithSAMLInput{
		PrincipalArn:    aws.String(principal),
		RoleArn:         aws.String(role),
		SAMLAssertion:   aws.String(string(assertion.RawData)),
		DurationSeconds: aws.Int64(int64(duration.Seconds())),
	}

	samlResp, err := svc.AssumeRoleWithSAML(samlParams)
	if err != nil {
		log.WithField("role", role).Errorf(
			"error assuming role with SAML: %s", err.Error())
		return sts.Credentials{}, "", err
	}

	var sessionCookie string
	cookies := o.CookieJar.Cookies(o.BaseURL)
	for _, cookie := range cookies {
		if cookie.Name == "sid" {
			sessionCookie = cookie.Value
		}
	}

	return *samlResp.Credentials, sessionCookie, nil
}

func selectMFADevice(factors []OktaUserAuthnFactor) (*OktaUserAuthnFactor, error) {
	if len(factors) > 1 {
		log.Info("Select a MFA from the following list")
		for i, f := range factors {
			log.Infof("%d: %s (%s)", i, f.Provider, f.FactorType)
		}
		i, err := Prompt("Select MFA method", false)
		if err != nil {
			return nil, err
		}
		factor, err := strconv.Atoi(i)
		if err != nil {
			return nil, err
		}
		return &factors[factor], nil
	} else if len(factors) == 1 {
		return &factors[0], nil
	}
	return nil, errors.New("Failed to select MFA device")
}

func (o *OktaClient) preChallenge(oktaFactorId, oktaFactorType string) ([]byte, error) {
	var mfaCode string
	var err error
	//Software and Hardware based OTP Tokens
	if strings.Contains(oktaFactorType, "token") {
		log.Debug("Token MFA")
		mfaCode, err = Prompt("Enter MFA Code", false)
		if err != nil {
			return nil, err
		}
	} else if strings.Contains(oktaFactorType, "sms") {
		log.Debug("SMS MFA")
		payload, err := json.Marshal(OktaStateToken{
			StateToken: o.UserAuth.StateToken,
		})
		if err != nil {
			return nil, err
		}
		var sms interface{}
		log.Debug("Requesting SMS Code")
		err = o.Get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify",
			payload, &sms, "json",
		)
		if err != nil {
			return nil, err
		}
		mfaCode, err = Prompt("Enter MFA Code from SMS", false)
		if err != nil {
			return nil, err
		}
	}
	payload, err := json.Marshal(OktaStateToken{
		StateToken: o.UserAuth.StateToken,
		PassCode:   mfaCode,
	})
	if err != nil {
		return nil, err
	}
	return payload, nil
}

func (o *OktaClient) postChallenge(payload []byte, oktaFactorId string) error {
	//Initiate Duo Push Notification
	if o.UserAuth.Status == "MFA_CHALLENGE" {
		f := o.UserAuth.Embedded.Factor

		o.DuoClient = &DuoClient{
			Host:       f.Embedded.Verification.Host,
			Signature:  f.Embedded.Verification.Signature,
			Callback:   f.Embedded.Verification.Links.Complete.Href,
			StateToken: o.UserAuth.StateToken,
		}

		log.Debugf("Host:%s\nSignature:%s\nStateToken:%s\n",
			f.Embedded.Verification.Host, f.Embedded.Verification.Signature,
			o.UserAuth.StateToken)

		errChan := make(chan error, 1)
		go func() {
			log.Debug("challenge u2f")
			log.Info("Sending Push Notification...")
			err := o.DuoClient.ChallengeU2f()
			if err != nil {
				errChan <- err
			}
		}()

		// Poll Okta until Duo authentication has been completed
		for o.UserAuth.Status != "SUCCESS" {
			select {
			case duoErr := <-errChan:
				if duoErr != nil {
					return errors.New("Failed Duo challenge")
				}
			default:
				err := o.Get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify",
					payload, &o.UserAuth, "json",
				)
				if err != nil {
					return err
				}
			}
			time.Sleep(2 * time.Second)
		}
	}
	return nil
}

func (o *OktaClient) challengeMFA() (err error) {
	var oktaFactorId string
	var payload []byte
	var oktaFactorType string

	log.Debugf("%s", o.UserAuth.StateToken)
	factor, err := selectMFADevice(o.UserAuth.Embedded.Factors)
	if err != nil {
		log.Debug("Failed to select MFA device")
		return
	}
	oktaFactorId, err = GetFactorId(factor)
	if err != nil {
		return
	}
	oktaFactorType = factor.FactorType
	if oktaFactorId == "" {
		return
	}
	log.Debugf("Okta Factor ID: %s", oktaFactorId)
	log.Debugf("Okta Factor Type: %s", oktaFactorType)

	payload, err = o.preChallenge(oktaFactorId, oktaFactorType)

	err = o.Get("POST", "api/v1/authn/factors/"+oktaFactorId+"/verify",
		payload, &o.UserAuth, "json",
	)
	if err != nil {
		return
	}

	//Handle Duo Push Notification
	err = o.postChallenge(payload, oktaFactorId)
	if err != nil {
		return err
	}
	return
}

func GetFactorId(f *OktaUserAuthnFactor) (id string, err error) {
	switch f.FactorType {
	case "web":
		id = f.Id
	case "token:software:totp":
		id = f.Id
	case "token:hardware":
		id = f.Id
	case "sms":
		id = f.Id
	default:
		err = fmt.Errorf("factor %s not supported", f.FactorType)
	}
	return
}

func (o *OktaClient) Get(method string, path string, data []byte, recv interface{}, format string) (err error) {
	var res *http.Response
	var body []byte
	var header http.Header
	var client http.Client

	url, err := url.Parse(fmt.Sprintf(
		"https://%s.%s/%s", o.Organization, OktaServer, path,
	))
	if err != nil {
		return err
	}

	if format == "json" {
		header = http.Header{
			"Accept":        []string{"application/json"},
			"Content-Type":  []string{"application/json"},
			"Cache-Control": []string{"no-cache"},
		}
	} else {
		header = http.Header{}
	}

	client = http.Client{
		Jar: o.CookieJar,
	}
	req := &http.Request{
		Method:        method,
		URL:           url,
		Proto:         "HTTP/1.1",
		ProtoMajor:    1,
		ProtoMinor:    1,
		Header:        header,
		Body:          ioutil.NopCloser(bytes.NewReader(data)),
		ContentLength: int64(len(body)),
	}

	if res, err = client.Do(req); err != nil {
		return
	}
	defer res.Body.Close()

	if res.StatusCode != http.StatusOK {
		err = fmt.Errorf("%s %v: %s", method, url, res.Status)
	} else if recv != nil {
		switch format {
		case "json":
			err = json.NewDecoder(res.Body).Decode(recv)
		default:
			var rawData []byte
			rawData, err = ioutil.ReadAll(res.Body)
			if err != nil {
				return
			}
			if err := ParseSAML(rawData, recv.(*SAMLAssertion)); err != nil {
				return fmt.Errorf("Okta user %s does not have the AWS app added to their account.  Please contact your Okta admin to make sure things are configured properly.", o.Username)
			}
		}
	}

	return
}

type OktaProvider struct {
	Keyring         keyring.Keyring
	ProfileARN      string
	SessionDuration time.Duration
	OktaAwsSAMLUrl  string
}

func (p *OktaProvider) Retrieve() (sts.Credentials, string, error) {
	log.Debug("using shib provider")
	item, err := p.Keyring.Get("shib-creds")
	if err != nil {
		log.Debug("couldnt get shib creds from keyring: %s", err)
		return sts.Credentials{}, "", err
	}

	var oktaCreds OktaCreds
	if err = json.Unmarshal(item.Data, &oktaCreds); err != nil {
		return sts.Credentials{}, "", errors.New("Failed to get shib credentials from your keyring.  Please make sure you have added shib credentials with `aws-okta add`")
	}


	//Start JMA Code here
	resp, err := soup.Get(idpentryurl)
	if err != nil {
		return sts.Credentials{}, "", errors.New("Failed to access Shibboleth URL")
	}
	log.Debug("Step: 1")
	doc := soup.HTMLParse(resp)
	inputs := doc.FindAll("input")
	payload := url.Values{}
	for _, input := range inputs {
		var name = input.Attrs()["name"]
		var value = input.Attrs()["value"]
		if (strings.Contains(strings.ToLower(name),"user")) {
			payload.Add(name,oktaCreds.Username)
		} else if (strings.Contains(strings.ToLower(name),"email")) {
			payload.Add(name,oktaCreds.Username)
		} else if (strings.Contains(strings.ToLower(name),"pass")) {
			payload.Add(name,oktaCreds.Password)
		} else if (strings.Contains(strings.ToLower(name),"revoke")) {
			//fmt.Println("Not setting revoke attribute")
		} else {
			payload.Add(name, value)
		}
	}
	payload.Add("_eventId_proceed", "")

	formaction := doc.Find("form").Attrs()["action"]
	idpurl, err := url.Parse(idpentryurl)
	if err != nil {
		fmt.Println(err)
	}
	var idpauthformsubmiturl = idpurl.Scheme + "://" + idpurl.Host + formaction

	var resp2, _ = http.PostForm(idpauthformsubmiturl, payload)
	defer resp2.Body.Close()
	bytes, err := ioutil.ReadAll(resp2.Body)

	//Duo challenge goes here
  log.Debug("Step: 3")
	var assertion = ""
	doc = soup.HTMLParse(string(bytes))
	inputs = doc.FindAll("input")
	for _, input := range inputs {
		var name = input.Attrs()["name"]
		if (strings.Contains(name,"SAMLResponse")) {
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
