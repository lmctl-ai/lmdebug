# Standard `lmcode` REST Endpoints & Stateless CLI Interfaces

## Summary

`lmdebug` supports the 226-signature `lmcode_std_v3` standard catalog (`@lmctl-ai/lmctl@0.2.482`):
- Scripts can implement the 10 standard REST and stateless CLI interfaces (`RestGet`, `RestPost`, `RestPut`, `RestDelete`, `RestPatch`, `RestHead`, `RestOptions`, `RestHandler`, `CliCommand`, `CliOption`) with `@"..."` path/command/flag annotations and `RestExchange` request/response methods.
- `rest_config`, `rest_route`, `rest_serve`, `rest_stop`, and `rest_cli` dispatch stateless CLI arguments or HTTP requests against `lmdebug` domain contexts (`net`, `sys`, `proc`, `detect`, `shark`, `lmdebug`).
- Verified in `test.sh` and `.github/workflows/public-ci.yml` against `@lmctl-ai/lmctl@0.2.482`.
