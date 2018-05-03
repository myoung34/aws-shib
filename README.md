# aws-shib

`aws-shib` allows you to authenticate with AWS using your Shibboleth credentials.

## Installing


## Usage

### Adding Okta credentials

```bash
$ aws-shib add
```

This will prompt you for your Shibboleth URL for AWS, username, and password.  These credentials will then be stored in your keyring for future use.  You can also be prompted on each use if you prefer not to store these credentials in your keyring

### Exec

```bash
$ aws-shib exec <profile> -- <command>
```

Exec will assume the role specified by the given aws config profile and execute a command with the proper environment variables set.  This command is a drop-in replacement for `aws-vault exec` and accepts all of the same command line flags:

```bash
$ aws-shib help exec
exec will run the command specified with aws credentials set in the environment

Usage:
  aws-shib exec <profile> -- <command>

Flags:
  -a, --assume-role-ttl duration   Expiration time for assumed role (default 15m0s)
  -h, --help                       help for exec
  -t, --session-ttl duration       Expiration time for okta role session (default 1h0m0s)

Global Flags:
  -b, --backend string   Secret backend to use [kwallet secret-service file] (default "file")
  -d, --debug            Enable debug logging
```


### Configuring your aws config

`aws-shib` assumes that your Shibboleth has already been set up to integrate with AWS (and optionally Duo) such that you can log in with a URL like:
https://***REMOVED***/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices


 You will need to set the default value in your `~/.aws/config` file, for example:

```ini
[okta]
aws_saml_url = https://***REMOVED***/idp/profile/SAML2/Unsolicited/SSO?providerId=urn:amazon:webservices
```

Next, you need to set up at least one role.    It should be specified like any other aws profile:

```ini
[profile shib-sandbox]
role_arn = arn:aws:iam::***REMOVED***:role/Shibboleth-OIT-SysAdmin
region = us-west-2
```

Your setup may require additional roles to be configured if your admin has set up a more complicated role scheme like cross account roles.  For more details on the authentication process, see the internals section.

#### A more complex example

The `aws_saml_url` can be set in the "okta" ini section, or on a per profile basis. This is useful if, for example, your organization has several Okta Apps (i.e. one for dev/qa and one for prod, or one for internal use and one for integrations with third party providers). For example:

```ini
[okta]
# This is the "default" Okta App
aws_saml_url = home/amazon_aws/cuZGoka9dAIFcyG0UllG/214

[profile dev]
# This profile uses the default Okta app
role_arn = arn:aws:iam::<account-id>:role/<okta-role-name>

[profile integrations-auth]
# This is a distinct Okta App
aws_saml_url = home/amazon_aws/woezQTbGWUaLSrYDvINU/214
arn:aws:iam::<account-id>:role/<okta-role-name>

```

The configuration above means that you can use multiple Shibboleth IDPs at the same time and switch between them easily.

## Backends

We use 99design's keyring package that they use in `aws-vault`.  Because of this, you can choose between different pluggable secret storage backends just like in `aws-vault`.  You can either set your backend from the command line as a flag, or set the `AWS_OKTA_BACKEND` environment variable.


## Internals

### Authentication process

We use the following multiple step authentication:

- Step 1 : Basic authentication against Shibboleth web form
- Step 2 : MFA challenge if required
- Step 3 : Get AWS SAML assertion from Shibboleth
- Step 4 : Assume the requested AWS Role from the targeted AWS account to generate STS credentials
