# kospi-parser

### Generate parser binary

**nix**
``` sh
nix-shell # Use the shell.nix to provide an environment with pcap
ghc Main.hs -o parse-quote # Compile the parser binary
```

**cabal**
``` sh
cabal v2-build
```


### Run parser

``` sh
./parse-quote <pcap file>    # unordered output
./parse-quote -r <pcap file> # outputs packets by accept times
```

