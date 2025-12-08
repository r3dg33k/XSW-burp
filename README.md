# XML Signature Wrapping (XSW) Burp Suite Extension

XSW Burp Suite Extension automates the process of probing SAML endpoints for Signature Wrapping vulnerabilities.

## How to
1.	Right-click on Authentication request at Burp Suite and choose "WRAP Attack". 
2.  Configure the dialog parameters and start the test. 
3.  The extension automatically generates multiple crafted XML payloads and sends them to the target endpoint. 
4.  The results are logged in Burp Suite’s Extensions Organizer tab for further analysis.

## Settings

-	Name ID - The user identity to impersonate (typically an email address).
-	Assertion URL (target) - *Optional.* The Assertion Consumer Service (ACS) URL to target, if it is not already included in the AuthnRequest.
-	Metadata URL (signed XML source) - *Optional.* URL to the signed metadata document (usually the IdP’s signed metadata).
-	Timeout - *Optional.* Delay between requests, in milliseconds.
-	Always Refresh Metadata - *Optional.* When enabled, the extension fetches a fresh signed metadata document for every test case.

## Attacks

The extension probes multiple classes of Signature Wrapping vulnerabilities, including:
- Attribute Pollution - parser discrepancies between libxml2 and REXML.
- Namespace Confusion - bypasses based on namespace redefinition and prefix ambiguity.
- Void Canonicalization - exploit libxml2 c14n limitations

## Samples
[Golden-SAMLResponse.xml](samples/Golden-SAMLResponse.xml) 

## Reference

This extension is inspired by [SAMLRaider](https://github.com/CompassSecurity/SAMLRaider) extension and 
based on techniques introduced in the research paper:
[The Fragile Lock: Novel Bypasses for SAML Authentication](https://portswigger.net/research/the-fragile-lock) by [Zak Fedotkin](https://x.com/zakfedotkin)

## Demo

Following **gitlab-ee:17.8.4** docker-compose project can be used to reproduce the issue for demo purposes only. 
Replace the following with your own IdP values:

- `idp_cert_fingerprint: "<idp_cert_fingerprint>"`
- `idp_sso_target_url: "<idp_sso_target_url>"`

```yml
version: '3.6'
services:
  gitlab:
    image: gitlab/gitlab-ee:17.8.4-ee.0
    container_name: gitlab
    restart: always
    hostname: 'gitlab.lab.local'
    environment:
      GITLAB_OMNIBUS_CONFIG: |
        external_url 'https://gitlab.lab.local'
        nginx['listen_port'] = 443
        nginx['redirect_http_to_https'] = true
        nginx['ssl_certificate'] = "/etc/ssl/certs/gitlab/server-cert.pem"
        nginx['ssl_certificate_key'] = "/etc/ssl/certs/gitlab/server-key.pem"
        nginx['ssl_protocols'] = "TLSv1.1 TLSv1.2"
        nginx['logrotate_frequency'] = "weekly"
        nginx['logrotate_rotate'] = 52
        nginx['logrotate_compress'] = "compress"
        nginx['logrotate_method'] = "copytruncate"
        nginx['logrotate_delaycompress'] = "delaycompress"
        gitlab_rails['gitlab_shell_ssh_port'] = 2424
        gitlab_rails['omniauth_allow_single_sign_on'] = ['saml']
        gitlab_rails['omniauth_block_auto_created_users'] = false
        gitlab_rails['omniauth_auto_link_saml_user'] = true
        gitlab_rails['omniauth_providers'] = [
          {
            name: "saml",
            label: "Okta login",
            args: {
              assertion_consumer_service_url: "https://gitlab.lab.local/users/auth/saml/callback",
              idp_cert_fingerprint: "<idp_cert_fingerprint>",
              idp_sso_target_url: "<idp_sso_target_url>",
              issuer: "https://gitlab.lab.local",
              name_identifier_format: "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
            }
          }
        ]
    ports:
      - '80:80'
      - '443:443'
      - '2424:22'
    volumes:
      - '/srv/gitlab/config:/etc/gitlab'
      - '/srv/gitlab/logs:/var/log/gitlab'
      - '/srv/gitlab/data:/var/opt/gitlab'
      - './volume_data/ssl:/etc/ssl/certs/gitlab'
    shm_size: '256m'
```