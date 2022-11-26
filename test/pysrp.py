#! /usr/bin/env python3
'''Generates all the pyrsp reference values used in the Dart unit tests.'''

# Be sure to install srp: pip3 install srp
# Source: https://github.com/cocagne/pysrp
import srp

# Same defaults as used by dsrp.
N_str = 'EEAF0AB9ADB38DD69C33F80AFA8FC5E86072618775FF3C0B9EA2314C9C256576D674DF7496EA81D3383B4813D692C6E0E0D5D8E250B98BE48E495C1D6089DAD15DC7D7B46154D6B6CE8EF4AD69B15D4982559B297BCF1885C529F566660E57EC68EDBC3C05726CC02FD4CBF4976EAA9AFD5138FE8376435B9FC61D2FC0EB06E3'
N = bytes(N_str, 'ascii')
g_int = 2
g = bytes(str(g_int), 'ascii')

DEFAULT_VERIFIER_KEY = bytes([38, 173, 182, 68, 210, 122, 188, 207, 48, 253, 137, 75, 207, 161, 251, 108, 245, 255, 167, 202, 206, 107, 158, 251, 195, 6, 65, 137, 17, 179, 102, 100, 132, 48, 113, 113, 254, 245, 45, 219, 237, 31, 6, 151, 191, 168, 83, 66, 207, 8, 199, 134, 190, 75, 220, 9, 64, 121, 240, 52, 222, 188, 154, 105, 197, 164, 250, 30, 23, 49, 82, 177, 226, 142, 206, 13, 62, 99, 124, 227, 216, 71, 207, 125, 238, 243, 140, 229, 240, 97, 59, 147, 196, 207, 25, 45, 131, 40, 142, 179, 207, 120, 248, 12, 44, 30, 132, 18, 146, 181, 40, 228, 93, 61, 150, 122, 135, 109, 223, 183, 117, 30, 161, 177, 76, 29, 39, 62])
DEFAULT_SALT = bytes([179, 213, 23, 45])
DEFAULT_EPHEMERAL_PRIVATE_USER_KEY = bytes([232, 70, 157, 38, 48, 237, 179, 190, 222, 91, 132, 27, 167, 190, 150, 98, 47, 119, 182, 249, 138, 180, 194, 124, 66, 153, 178, 125, 47, 149, 55, 73])
# DEFAULT_EPHEMERAL_PUBLIC_USER_KEY = bytes([29, 113, 4, 60, 247, 47, 198, 246, 163, 32, 118, 226, 28, 13, 19, 229, 222, 253, 239, 86, 212, 251, 233, 233, 51, 204, 128, 73, 79, 249, 74, 249, 67, 146, 129, 247, 138, 26, 215, 37, 149, 5, 31, 174, 111, 111, 247, 182, 198, 246, 30, 215, 103, 100, 184, 188, 97, 197, 217, 193, 37, 158, 126, 188, 163, 74, 78, 110, 139, 10, 1, 206, 130, 233, 247, 169, 10, 183, 35, 60, 205, 167, 122, 124, 53, 99, 125, 24, 11, 16, 107, 18, 69, 135, 79, 9, 180, 7, 98, 27, 40, 225, 210, 216, 164, 162, 120, 175, 43, 244, 75, 138, 187, 116, 118, 112, 181, 21, 99, 121, 101, 244, 28, 125, 179, 50, 175, 120])
DEFAULT_EPHEMERAL_PRIVATE_SERVER_KEY = bytes([249, 172, 205, 98, 151, 175, 247, 226, 73, 122, 213, 193, 100, 74, 31, 109, 129, 146, 171, 18, 219, 111, 139, 9, 43, 164, 171, 1, 17, 251, 155, 217])
# DEFAULT_EPHEMERAL_PUBLIC_SERVER_KEY = bytes([48, 253, 127, 208, 252, 27, 19, 242, 204, 44, 60, 7, 136, 100, 251, 46, 140, 252, 127, 151, 252, 16, 29, 255, 246, 21, 160, 46, 124, 121, 153, 62, 73, 241, 233, 170, 173, 83, 15, 25, 245, 199, 107, 205, 73, 179, 55, 94, 238, 125, 99, 166, 95, 96, 178, 124, 155, 158, 137, 76, 225, 82, 97, 61, 235, 223, 232, 138, 218, 8, 109, 72, 165, 152, 87, 7, 48, 95, 52, 96, 73, 11, 65, 33, 181, 67, 197, 237, 4, 166, 56, 9, 140, 229, 191, 220, 134, 98, 44, 133, 87, 119, 57, 233, 229, 210, 96, 45, 217, 59, 192, 162, 229, 200, 32, 210, 5, 88, 76, 193, 104, 158, 238, 56, 142, 191, 86, 61])

USERNAME = 'brown'
PASSWORD = 'cow'

# Enable RFC5054 compatibility for interoperation with non pysrp
# SRP-6a implementations.
srp.rfc5054_enable()

# The salt and verifier returned from srp.create_salted_verification_key() should be
# stored on the server.
# salt, verifier_key = srp.create_salted_verification_key(
#     USERNAME, PASSWORD,
#     hash_alg=srp.SHA256,
#     # ng_type=srp.NG_1024,
#     ng_type=srp.NG_CUSTOM, n_hex=N, g_hex=g,
# )
salt = DEFAULT_SALT
verifier_key = DEFAULT_VERIFIER_KEY
print('salt, verifier_key:', list(salt), list(verifier_key))

# user = srp.User(USERNAME, PASSWORD,
#                 hash_alg=srp.SHA256,
#                 # ng_type=srp.NG_1024,
#                 ng_type=srp.NG_CUSTOM, n_hex=N, g_hex=g,
#                 bytes_a=DEFAULT_EPHEMERAL_PRIVATE_USER_KEY
#                 )

# # ephemeralPrivateUserKey = user.get_ephemeral_secret()
# _, ephemeralPublicUserKey = user.start_authentication()
# print('ephemeralPrivateUserKey:', list(user.get_ephemeral_secret()))
# print('ephemeralPublicUserKey:', list(ephemeralPublicUserKey))

#TODO: create new default salt and verifier key.
server = srp.Verifier(USERNAME, salt, verifier_key,
                      # bytes_A=ephemeralPublicUserKey,
                      hash_alg=srp.SHA256,
                      # ng_type=srp.NG_1024,
                      ng_type=srp.NG_CUSTOM, n_hex=N, g_hex=g,
                      bytes_b=DEFAULT_EPHEMERAL_PRIVATE_SERVER_KEY
                      )
_, ephemeralPublicServerKey = server.get_challenge()
print('ephemeralPrivateServerKey:', list(server.get_ephemeral_secret()))
print('ephemeralPublicServerKey:', list(ephemeralPublicServerKey))
import ipdb
ipdb.set_trace()

sessionKeyVerifier = user.process_challenge(salt, ephemeralPublicServerKey)
print('sessionKeyVerifier:', list(sessionKeyVerifier))

serverSessionKeyVerifier = server.verify_session(sessionKeyVerifier, ephemeralPublicUserKey)
print('serverSessionKeyVerifier:', list(serverSessionKeyVerifier))

user.verify_session(serverSessionKeyVerifier)
# NOTE: get_session_key only returns a value after verify_session.
print('sessionKey:', list(user.get_session_key()))

assert user.authenticated()
assert server.authenticated()
