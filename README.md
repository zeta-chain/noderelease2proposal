## noderelease2proposal

Easily generate cosmovisor compliant upgrade proposals from [node](https://github.com/zeta-chain/node) releases.

### Usage

```
go run . https://github.com/zeta-chain/node/releases/tag/v14.0.1 > proposal.json
```

or

```
go install github.com/zeta-chain/noderelease2proposal@latest
noderelease2proposal https://github.com/zeta-chain/node/releases/tag/v14.0.1 > proposal.json
```

You may also provide an RPC url and a RFC3339 timestamp to automatically estimate the block height:

```
noderelease2proposal --rpc-url https://develop-cometbft-1.zetachain.network --upgrade-time '2024-05-27T09:00:00-07:00' https://github.com/zeta-chain/node/releases/tag/v16.0.0 > proposal.json
2024/05/24 12:45:08 got latest block height: 5759
2024/05/24 12:45:09 calculated we to wait 105204 more blocks. 2.335370731s per block. 68h14m50.735089889s until target time.
2024/05/24 12:45:10 deposit is for example only and need to be configured correctly
```

### Pretty Print Upgrade info

```
cat proposal.json > ./pretty_print_info.json
```