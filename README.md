# XML Signature Wrapping (XSW) Burp Suite Extension

XSW Burp Suite Extension automates the process of probing SAML endpoints for Signature Wrapping vulnerabilities, 
including newly discovered classes described in the whitepaper “The Fragile Lock: Novel Bypasses for SAML Authentication.”

## How to
1.	Right-click on Authentication request at Burp Suite and choose "WRAP Attack". 
2.  Configure the dialog parameters and start the test. 
3.  The extension automatically generates multiple crafted XML payloads and sends them to the target endpoint. 
4.  The results are logged in Burp Suite’s Extensions Organizer tab for further analysis.

## Settings

-	Name ID - The user identity to impersonate (typically an email address).
-	Assertion URL - *Optional.* The Assertion Consumer Service (ACS) URL to target, if it is not already included in the AuthnRequest.
-	Metadata URL - *Optional.* URL to the signed metadata document (usually the IdP’s signed metadata).
-	Timeout - *Optional.* Delay between requests, in milliseconds.
-	Self-Sign - *Optional.* When enabled, the extension attempts to self-sign the SAML Response and Assertion to support advanced testing scenarios.
-	Always Refresh Metadata - *Optional.* When enabled, the extension fetches a fresh signed metadata document for every test case.

## Attacks

The extension probes multiple classes of Signature Wrapping vulnerabilities, including:
- Attribute Pollution - parser discrepancies between libxml2 and REXML.
- Namespace Confusion - bypasses based on namespace redefinition and prefix ambiguity.


## Reference


This extension is inspired by [SAMLRaider](https://github.com/CompassSecurity/SAMLRaider) extension and 
based on techniques introduced in the research paper:
“The Fragile Lock: Novel Bypasses for SAML Authentication”  by Zakhar Fedotkin
