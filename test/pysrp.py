#! /usr/bin/env python3
# Be sure to install srp: pip3 install srp
# Source: https://github.com/cocagne/pysrp
import srp

# N and g from RFC5054 Appendix A section 1.
# Used for easy comparison with Dart implementation.
N = 'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3'
g = '2'

# Enable RFC5054 compatibility for interoperation with non pysrp
# SRP-6a implementations.
srp.rfc5054_enable()

# The salt and verifier returned from srp.create_salted_verification_key() should be
# stored on the server.
salt, verifier_key = srp.create_salted_verification_key(
    'brown', 'cow',
    hash_alg=srp.SHA256,
    ng_type=srp.NG_CUSTOM,
    n_hex=N, g_hex=g,
)
print('salt, verifier_key:', list(salt), list(verifier_key))
