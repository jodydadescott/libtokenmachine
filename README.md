# libtokenmachine

libtokenmachine grants Secrets or Kerberos Keytabs to bearers of JWT Tokens authorized by
Open Policy Agent (OPA) Rego. Tokens2Secrets is a bridge between the old world of shared
secrets and Kerberos Keytabs and the new world of Tokens.

Kerberos works by issuing tickets to users or machines that prove their identity with
a username or principal and password. Daemonized applications, especially ones not part
of a Kerberos domain, are often assigned Keytabs. Keytabs are files generated by the
Directory Admin. A Keytab contains one or more principals and the corresponding password
that is encrypted with the directory secret. Keytabs can be used to obtain Kerberos
tickets. Note that most Keytabs hold only one principal.

A Keytab or more specifically the principal is valid until the account is disabled or the
password is changed. This creates a security hole as Keytabs are by there very nature
long lived. No one wants to go around and change them out all the time. Its lots of work
and something may go wrong. It is not uncommon for Keytabs to be valid for years.

Tokens have become very popular with the rise of companies such as AWS, Okta and Google.
The industry has gravitated towards JSON Web Tokens (JWT) and OAUTH/OIDC. These tokens
are analogus to Kerberos tickets but unlike Kerberos tickets they hold information about
the bearer and can be verified by third parties. This is because they include an issuer.
This allows for verification by fetching the issuers public key and validating the token
included signature.

This project seeks to provide a bridge between these two different worlds by issuing
Kerberos Keytabs to bearers of tokens with authorized claims (or tags). Authorization
is performed by executing an Open Policy Agent (OPA) Rego policy. If authorized the
bearer of said token will be issued a Keytab that will have a validity based on
preconfigured time periods.

Operatioally the process works like this. The bearer obtains a token from their identity
provider (IDP) and makes a request to the Tokens2Secrets server for a nonce. The
Tokens2Secrets server uses the bearers token to see if they are authorized to get a
nonce. If so a new nonce is created with an expiration time based on configuration and
returned to the bearer. The bearer then obtains a new token from their identity provider
with the audience (aud) field set to the nonce. This is to prevent a replay attack. The
bearer uses this new token to request a Keytab with a desired principal from the
Tokens2Secrets server. The Tokens2Secrets server validats the nonce and executes the OPA
policy to authorize that the bearer is entitled to the Keytab. If the bearer is entitiled
the Keytab is returned as a JSON object with both the Keytab file as a Base64 encoded
file and the Keytab expiration time.

It is important to understand that the Keytab expiration operates indepentley of the
request time. For example if the Keytab is configured for a five minute lifetime then
the Keytab expiration will be based on the five minute periods since epoch. So if the
Keytab is requested at 04:30 of a five minute period the bearer may or may not have
enough time to make effective use of the Keytab before expiration. In this situation
if is up to the bearer to check the expiration time and if necessary and request the
Keytab again if necessary. If this does happen the bearer can request the Keytab with
the same nonce as the nonce does not expire on use but on time. Note that the nonce
expiration is based on the creation of the nonce (unlike the Keytab).

In practice the bearer should request a Keytab, decoded the Base64 file to a scratch
file, obtain a Kerberos ticket and then discard the Keytab by deleting the file.

Tokens2Secrets may be ran on Windows, Linux or Darwin but valid Keytabs will only
be issued if running on Windows. This is because the utility ktpass.exe is used
to generate the Keytabs.

## Configuration

### Struct
Configuration is defined with the struct
```
type Config struct {
	Policy         string
	NonceLifetime  time.Duration
	SecretSecrets  []*Secret
	KeytabKeytabs  []*Keytab
	KeytabLifetime time.Duration
}
```

### Policy
Example Policy
```
package main

default auth_get_nonce = false
default auth_get_keytab = false
default auth_get_secret = false

auth_base {
   # Here we match that the token issuer is an authorized issuer
   input.claims.iss == "abc123"
}

auth_get_nonce {
  # For now all we are doing is calling auth_base. This could be expanded as needed.
   auth_base
}

auth_nonce {
   # To prevent replay attack we compare the nonce from the user with the nonce in
   # the token claims. Here we expect the nonce from the user to match the audience
   # (aud) field. If our token issuer uses a different claim we will need to adjust
   # as necessary.
   input.claims.aud == input.nonce
}

auth_get_keytab {
   # Here we auth the principals requested by the user. We use claims from the token
   # provider to determine is the bearer should be authorized. Our token provider has
   # the authorized principals in a comma delineated string under the string array
   # service which is under the claims. We split the comma string into a set and
   # check for a match
   auth_base
   split(input.claims.service.keytab,",")[_] == input.principal
}

auth_get_secret {
   # Verify that the request nonce matches the expected nonce. Our token provider
   # has the nonce in the audience field under claims
   auth_base
   auth_nonce
}
```