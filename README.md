# keccak

[![Travis
CI](https://img.shields.io/travis/aupiff/keccak.svg?label=Travis%20CI)](https://travis-ci.org/aupiff/keccak)

A pure haskell implementation of the keccak family of hashes.

Documentation available on
[Hackage](http://hackage.haskell.org/package/keccak).

## Example usage

In the example usage below, I encode `ByteString`s in base16 so that they
can be read as standard hex strings.

```haskell
ghci> import Data.ByteString.Base16 as BS16

ghci> :t keccak256
keccak256 :: BS.ByteString -> BS.ByteString

ghci> BS16.encode $ keccak256 "testing"
"5f16f4c7f149ac4f9510d9cf8cf384038ad348b3bcdc01915f95de12df9d1b02"

ghci> BS16.encode $ keccak256 ""
"c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470"
```

## Testing

```
stack test
```

NIST uses the [Secure Hash Algorithm Validation System
(SHAVS)](https://csrc.nist.gov/CSRC/media//Projects/Cryptographic-Algorithm-Validation-Program/documents/shs/SHAVS.pdf)
to validate the correctness of hash implementations. For all four variants of
SHA3 and Keccak and the two standard variants of SHAKE, the `keccak` library's
implementations successfully
[pass](https://github.com/aupiff/keccak/blob/master/test/Spec.hs) the standard
KATs (Known Answer Tests).

## Benchmarks

```
stack bench
```

`cryptonite`'s C-based implementation of Keccack256 is currently 21 times faster
than my Haskell.

```
benchmarked keccak
time                 768.3 μs   (758.7 μs .. 775.7 μs)
                     0.998 R²   (0.995 R² .. 0.999 R²)
mean                 774.2 μs   (767.5 μs .. 784.0 μs)
std dev              29.27 μs   (23.12 μs .. 36.87 μs)
variance introduced by outliers: 19% (moderately inflated)

benchmarked cryptonite-keccak
time                 36.92 μs   (35.95 μs .. 38.03 μs)
                     0.996 R²   (0.995 R² .. 0.998 R²)
mean                 36.27 μs   (35.99 μs .. 36.66 μs)
std dev              1.147 μs   (918.3 ns .. 1.471 μs)
variance introduced by outliers: 14% (moderately inflated)
```

Eventually, I hope the library will have very few dependencies (only base,
vector & bytestring, currently) and excellent performance.

## References

[Cryptographic Sponge Functions](https://keccak.team/files/CSF-0.1.pdf)

[Official Keccak Reference](https://keccak.team/files/Keccak-reference-3.0.pdf)

[Specification summary](https://keccak.team/keccak_specs_summary.html)
