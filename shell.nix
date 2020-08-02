{ pkgs ? import <nixpkgs> {} }:

with pkgs;

let
  my-ghc = haskellPackages.ghcWithPackages ( pkgs: [
    haskellPackages.pcap haskellPackages.attoparsec
  ] );

in
  stdenv.mkDerivation {
    name = "haskell-env";
    buildInputs = [
      ghcid my-ghc
    ];
  }
