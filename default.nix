{ pkgs ? import ((import <nixpkgs> {}).fetchFromGitHub {
    owner = "NixOS";
    repo = "nixpkgs";
    rev = "a0aeb23";
    sha256 = "04dgg0f2839c1kvlhc45hcksmjzr8a22q1bgfnrx71935ilxl33d";
  }){}
, haddock ? true
}:
let
  inherit (pkgs.haskell.lib) buildFromSdist enableCabalFlag sdistTarball buildStrictly;
  inherit (pkgs.haskell.packages) ghc802 ghcjs;
  inherit (pkgs.lib) overrideDerivation optionalString;
  inherit (pkgs.stdenv) isDarwin;
  inherit (pkgs) closurecompiler;
  keccak-ghc = ghc802.callPackage ./keccak-ghc.nix { };
  keccak-ghcjs = ghcjs.callPackage ./keccak-ghcjs.nix { };
  keccak = {
    keccak-ghcjs = buildStrictly keccak-ghcjs;
    keccak-ghc = buildStrictly keccak-ghc;
  };
in keccak
