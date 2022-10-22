#! /usr/bin/env python3
'''Generates large 2048-bit safe primes suitable for use in SRP.'''
from sympy.ntheory import isprime, primefactors
import gensafeprime

# User parameters - modify these to your desire!
PRIME_BIT_LENGTH = 2048
DESIRED_GENERATOR = 2

################################################################################

def find_generator(prime):
    '''Find generator of the multiplicative group of integers modulo `prime`.

    Based on algorithm proposed here: https://crypto.stackexchange.com/a/89178/83069
    '''
    factors = primefactors(prime - 1)
    # print('Prime factors:', factors)
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


def verify_safe_prime(prime):
    '''Verifies safe prime and its generator has the required properties.

    Returns the generator.
    '''
    prime_bin = bin(prime)
    ## Verify bit length.
    assert len(prime_bin[2:]) == PRIME_BIT_LENGTH
    ## Check highest bit is 1 to ensure it is a large prime.
    assert prime_bin[2] == '1'
    ## Verify it is prime.
    assert isprime(prime)
    ## Verify it a safe prime (i.e., that it has a corresponding Sophie Germain prime).
    # N = 2p + 1 => p = (N - 1) / 2
    sophie_germain_prime = (prime - 1) // 2
    assert prime == 2 * sophie_germain_prime + 1
    assert isprime(sophie_germain_prime)
    ## Verify multiplicative generator is the one desired.
    generator = find_generator(prime)
    assert generator == DESIRED_GENERATOR
    return generator


iteration_count = 0
safe_prime = None
generator = None
while not safe_prime:
    print('Iteration', iteration_count)
    # Generate safe prime using OpenSSL.
    candidate_safe_prime = gensafeprime.generate(PRIME_BIT_LENGTH)
    try:
        generator = verify_safe_prime(candidate_safe_prime)
    except AssertionError:
        iteration_count += 1
        continue
    safe_prime = candidate_safe_prime
print('Safe prime:', safe_prime)
print('Safe prime hex:', hex(safe_prime))
print('Generator:', generator)
