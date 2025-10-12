## Generate Safe Primes for SRP

A Python 3 script for generating safe primes for SRP.

### Why

Pre-published safe primes such as those published in RFC5054 have
likely been incorporated into pre-computed attacks, which may
significantly reduce the compute time needed to infer the user
password and break SFC encryption from eons to hours or even minutes.

Thus it is recommended to generate and use your own safe primes.

### Usage

Running the script with `uv` to generate safe primes is easy:

```
uv run main.py
```

NOTE: This may take less than a second to more than five minutes due
to the nature of random search, how lucky you are, and how powerful
your computer is.

By default the script generates a 2048-bit safe prime as an integer
and hex. It also does some verification:
- sufficiently large (i.e., the highest bit is 1).
- it is in fact a safe prime.
- the generator of the mulitplicative group of integers modulus the
  safe prime is 2 (you may decide to use a different generator).

Increasing the number of bits or changing the desired generator can be done via the `-p`/`--prime-bit-length` and `-g`/`--generator` parameters. For example, to generate a 4096-bit safe prime with a generator of 4:

```
uv run main.py --prime-bit-length 4096 --generator 4
```
