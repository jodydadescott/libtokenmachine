#!/bin/bash

opa eval -i input.json -d policy.rego "auth_get_keytab = data.main.auth_get_keytab; auth_get_secret = data.main.auth_get_secret"