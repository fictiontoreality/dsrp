#! /usr/bin/env python3
'''Generates large 2048-bit safe primes suitable for use in SRP.'''
from sympy.ntheory import isprime, primefactors
import gensafeprime

PRIME_BIT_LENGTH = 2048

# Generate safe prime using OpenSSL.
safe_prime = gensafeprime.generate(PRIME_BIT_LENGTH)
print('Safe prime:', safe_prime)
safe_prime_bin = bin(safe_prime)
# print('binary form:', safe_prime_bin)

# Verify safe prime.
## Verify bit length.
assert len(safe_prime_bin[2:]) == PRIME_BIT_LENGTH
## Check highest bit is 1 to ensure it is a large prime.
assert safe_prime_bin[2] == '1'
## Verify it is prime.
assert isprime(safe_prime)
## Verify it a safe prime (i.e., that it has a corresponding Sophie Germain prime).
# N = 2p + 1 => p = (N - 1) / 2
sophie_germain_prime = (safe_prime - 1) // 2
assert safe_prime == 2 * sophie_germain_prime + 1
assert isprime(sophie_germain_prime)
## Verify multiplicative generator is 2.
def find_generator(prime):
    '''Find generator of the multiplicative the group of integers modulo `prime`.
    Based on algorithm proposed here: https://crypto.stackexchange.com/a/89178/83069
    '''
    factors = primefactors(prime - 1)
    print('Prime factors:', factors)
    # Avoid infinite loop.
    max_generator = 20
    for generator in range(2, max_generator + 1):
        found_generator = True
        for factor in factors:
            if pow(generator, (prime - 1) // factor, prime) == 1:
                found_generator = False
                break
        if found_generator:
            return generator
generator = find_generator(safe_prime)
print('Generator:', generator)
assert generator == 2
