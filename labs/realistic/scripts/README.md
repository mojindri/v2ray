# Lab Scripts

The Makefile is the primary entrypoint.

Keep shell scripts here small and boring:

- no hidden config mutation
- no provider-specific cloud logic
- write outputs under `../reports`
- fail fast with useful errors

Provider-specific provisioning belongs outside this repo unless the project
chooses one cloud provider explicitly.
