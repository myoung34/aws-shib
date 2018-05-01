package lib

import (
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"strings"
	"time"

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
