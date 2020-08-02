# kospi-parser

### Generate parser binary

``` sh
nix-shell # Use the shell.nix to provide an environment with pcap
ghc parse-quote.hs -o parse-quote # Compile the parser binary
```


### Run parser

``` sh
./parse-quote <pcap file>    # unordered output
./parse-quote -r <pcap file> # outputs packets by accept times
```

