{ pkgs ? import <nixpkgs> {} }:

with pkgs;

let
  my-ghc = haskellPackages.ghcWithPackages ( pkgs: [
    haskellPackages.pcap       # Bindings to libpcap
    haskellPackages.attoparsec # Bytestring parser
  ] );

in
  stdenv.mkDerivation {
    name = "haskell-env";
    buildInputs = [
      ghcid my-ghc
    ];
  }
