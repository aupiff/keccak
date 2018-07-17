# keccak

[![Travis
CI](https://img.shields.io/travis/aupiff/keccak.svg?label=Travis%20CI)](https://travis-ci.org/aupiff/keccak)

A pure haskell implementation of the keccak family of hashes.

## Example usage

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

## Benchmarks

```
stack bench
```

## References

[Cryptographic Sponge Functions](https://keccak.team/files/CSF-0.1.pdf)

[Official Keccak Reference](https://keccak.team/files/Keccak-reference-3.0.pdf)

[Specification summary](https://keccak.team/keccak_specs_summary.html)
