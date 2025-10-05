#! /usr/bin/env python3
'''Generates large safe primes suitable for use in SRP.'''
import argparse
from sympy.ntheory import isprime, primefactors
import gensafeprime

# Default parameters
DEFAULT_PRIME_BIT_LENGTH = 2048
DEFAULT_GENERATOR = 2

# Set the max generator of the multiplicative group to search for.
# Avoids an infinite loop when finding the generator.
MAX_GENERATOR = 20

################################################################################

def main():
    parser = argparse.ArgumentParser(
        description='Generates large safe primes suitable for use in SRP.'
    )
    parser.add_argument(
        '-g', '--generator',
        type=int,
        default=DEFAULT_GENERATOR,
        help=f'Desired generator (default: {DEFAULT_GENERATOR})'
    )
    parser.add_argument(
        '-p', '--prime-bit-length',
        type=int,
        default=DEFAULT_PRIME_BIT_LENGTH,
        help=f'Prime bit length (default: {DEFAULT_PRIME_BIT_LENGTH})'
    )
    args = parser.parse_args()

    iteration_count = 1
    safe_prime = None
    generator = None
    while not safe_prime:
        print('Iteration', iteration_count)
        # Generate safe prime using OpenSSL.
        candidate_safe_prime = gensafeprime.generate(args.prime_bit_length)
        try:
            generator = verify_safe_prime(candidate_safe_prime, args.prime_bit_length, args.generator)
        except AssertionError:
            iteration_count += 1
            continue
        safe_prime = candidate_safe_prime
    print('Safe prime:', safe_prime)
    print('Safe prime hex:', hex(safe_prime))
    print('Generator:', generator)


def find_generator(prime):
    '''Find generator of the multiplicative group of integers modulo `prime`.

    Based on algorithm proposed here: https://crypto.stackexchange.com/a/89178/83069
    '''
    factors = primefactors(prime - 1)
    # print('Prime factors:', factors)
    for generator in range(2, MAX_GENERATOR + 1):
        found_generator = True
        for factor in factors:
            if pow(generator, (prime - 1) // factor, prime) == 1:
                found_generator = False
                break
        if found_generator:
            return generator


def verify_safe_prime(prime, prime_bit_length, desired_generator):
    '''Verifies safe prime and its generator has the required properties.

    Returns the generator.
    '''
    prime_bin = bin(prime)
    ## Verify bit length.
    assert len(prime_bin[2:]) == prime_bit_length
    ## Check highest bit is 1 to ensure it is a large prime.
    assert prime_bin[2] == '1'
    ## Verify it is prime.
    assert isprime(prime)
    ## Verify it is a safe prime (i.e., that it has a corresponding Sophie Germain prime).
    # N = 2p + 1 => p = (N - 1) / 2
    sophie_germain_prime = (prime - 1) // 2
    assert prime == 2 * sophie_germain_prime + 1
    assert isprime(sophie_germain_prime)
    ## Verify multiplicative generator is the one desired.
    generator = find_generator(prime)
    assert generator == desired_generator
    return generator


if __name__ == '__main__':
    main()
