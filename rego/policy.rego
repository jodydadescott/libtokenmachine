package main

default auth_get_nonce = false
default auth_get_keytab = false
default auth_get_secret = false

# {
#   "claims": {
#     "alg": "EC",
#     "kid": "donut",
#     "iss": "abc123",
#     "exp": 1599844897,
#     "aud": "daisy",
#     "service": {
#       "keytab": "user1@example.com,user2@example.com"
#     }
#   },
#   "principal": "user1@example.com",
#   "nonces": ["daisy", "abigale", "poppy"]
# }

auth_base {
   # Match Issuer
   input.claims.iss == "abc123"
}

auth_get_nonce {
   auth_base
}

auth_nonce {
   # The input contains a set of all of the current valid nonces. For our
   # example here we expect the claim audience to have a nonce that will match
   # one of tne entries in the nonces set.
   input.nonces[_] == input.claims.aud
}

auth_get_keytab {
   # 1) Validate defaults with auth_base
   # 2) Validate the nonce with auth_nonce
   # 3) Validate the claims are allowed to obtain the keytab with the given name
   #    by checking to see if name exist in claim keytabs. We split the value
   #    on colon and look for any match.
   auth_base
   auth_nonce
   split(input.claims.service.keytabs,":")[_] == input.name
}

auth_get_secret {
   # 1) Validate defaults with auth_base
   # 2) Validate the nonce with auth_nonce
   # 3) Validate the claims are allowed to obtain the secret with the given name
   #    by checking to see if name exist in claim secrets. We split the value
   #    on comma and look for any match.
   auth_base
   auth_nonce
   split(input.claims.service.secrets,":")[_] == input.name
}