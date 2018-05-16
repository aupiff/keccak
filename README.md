# keccak

[![Travis
CI](https://img.shields.io/travis/aupiff/keccak.svg?label=Travis%20CI)](https://travis-ci.org/aupiff/keccak)

A pure haskell implementation of keccak.

## Example usage

```haskell
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

TODO

## References

[Official Keccak Refeerence](https://keccak.team/files/Keccak-reference-3.0.pdf)

[Specification summary](https://keccak.team/keccak_specs_summary.html)

[SHA-3 and The Hash Function Keccak (textbook chapter)](https://keccak.team/files/Keccak-reference-3.0.pdf)
