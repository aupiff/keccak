# keccak

[![Travis
CI](https://img.shields.io/travis/aupiff/keccak.svg?label=Travis%20CI)](https://travis-ci.org/aupiff/keccak)

A pure haskell implementation of the keccak family of hashes.

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
SHA3 and Keccak, the `keccak` library's implementations successfully
[pass](https://github.com/aupiff/keccak/blob/master/test/Spec.hs) the standard
KATs (Known Answer Tests).

## Benchmarks

```
stack bench
```

`cryptonite`'s C-based implementation of Keccack256 is currently 68x faster
than my naive, unoptimized Haskell.

```
benchmarked keccak
time                 438.7 μs   (429.6 μs .. 450.0 μs)
                     0.995 R²   (0.992 R² .. 0.997 R²)
mean                 440.7 μs   (435.8 μs .. 448.0 μs)
std dev              21.38 μs   (16.90 μs .. 28.45 μs)
variance introduced by outliers: 28% (moderately inflated)

benchmarked cryptonite-keccak
time                 6.319 μs   (6.187 μs .. 6.435 μs)
                     0.997 R²   (0.995 R² .. 0.998 R²)
mean                 6.446 μs   (6.354 μs .. 6.632 μs)
std dev              426.5 ns   (258.4 ns .. 737.4 ns)
variance introduced by outliers: 43% (moderately inflated)
```

Eventually, I hope the library will have very few dependencies (only base
& bytestring, currently) and excellent performance.

## References

[Cryptographic Sponge Functions](https://keccak.team/files/CSF-0.1.pdf)

[Official Keccak Reference](https://keccak.team/files/Keccak-reference-3.0.pdf)

[Specification summary](https://keccak.team/keccak_specs_summary.html)
