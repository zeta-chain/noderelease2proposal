## noderelease2proposal

Easily generate cosmovisor compliant upgrade proposals from [node](https://github.com/zeta-chain/node) releases.

### Usage

```
go run . https://github.com/zeta-chain/node/releases/tag/v14.0.1 > proposal.json
```

### Pretty Print Upgrade info

```
cat proposal.json > ./pretty_print_info.json
```