#! /usr/bin/env python3
# Be sure to install srp: pip3 install srp
# Source: https://github.com/cocagne/pysrp
import srp

# N and g from RFC5054 Appendix A section 1.
# Used for easy comparison with Dart implementation.
# Apparently the same values are used for ng_type=NG_1024.
N = 'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3'
g = '2'

default_verifier_key = bytes([38, 173, 182, 68, 210, 122, 188, 207, 48, 253, 137, 75, 207, 161, 251, 108, 245, 255, 167, 202, 206, 107, 158, 251, 195, 6, 65, 137, 17, 179, 102, 100, 132, 48, 113, 113, 254, 245, 45, 219, 237, 31, 6, 151, 191, 168, 83, 66, 207, 8, 199, 134, 190, 75, 220, 9, 64, 121, 240, 52, 222, 188, 154, 105, 197, 164, 250, 30, 23, 49, 82, 177, 226, 142, 206, 13, 62, 99, 124, 227, 216, 71, 207, 125, 238, 243, 140, 229, 240, 97, 59, 147, 196, 207, 25, 45, 131, 40, 142, 179, 207, 120, 248, 12, 44, 30, 132, 18, 146, 181, 40, 228, 93, 61, 150, 122, 135, 109, 223, 183, 117, 30, 161, 177, 76, 29, 39, 62])

username = 'brown'
password = 'cow'

# Enable RFC5054 compatibility for interoperation with non pysrp
# SRP-6a implementations.
srp.rfc5054_enable()

# The salt and verifier returned from srp.create_salted_verification_key() should be
# stored on the server.
salt, verifier_key = srp.create_salted_verification_key(
    username, password,
    hash_alg=srp.SHA256,
    ng_type=srp.NG_1024,
    # n_hex=N, g_hex=g,
)
print('salt, verifier_key:', list(salt), list(verifier_key))

ephemeralPrivateUserKey = bytes([232, 70, 157, 38, 48, 237, 179, 190, 222, 91, 132, 27, 167, 190, 150, 98, 47, 119, 182, 249, 138, 180, 194, 124, 66, 153, 178, 125, 47, 149, 55, 73])

user = srp.User(username, password,
                hash_alg=srp.SHA256,
                ng_type=srp.NG_1024,
                # n_hex=N, g_hex=g
                bytes_a=ephemeralPrivateUserKey)

# ephemeralPrivateUserKey = user.get_ephemeral_secret()
_, ephemeralPublicUserKey = user.start_authentication()
print('ephemeralPrivateUserKey:', list(ephemeralPrivateUserKey))
print('ephemeralPublicUserKey:', list(ephemeralPublicUserKey))
