# Architecture — Sentinel Vault (PS 9)

## Data Flow

```
Log sources (auth, file access, permission changes)
        |
        v
  log_generator.py  --->  logs.txt  (append-only log file)
        |
        v
  hash_windows.py
    - reads new lines from logs.txt every fixed window (default 5 min)
    - computes:  window_hash = SHA256(previous_window_hash + window_log_lines)
    - appends the record to hash_chain.json
        |
        v
  anchor_to_chain.py
    - reads hash_chain.json
    - for each window not yet anchored, calls the smart contract's
      anchorWindow(windowId, windowHash, previousHash, numLines)
    - the contract rejects re-anchoring a windowId that already exists,
      which is what makes a window's record permanent once anchored
        |
        v
  LogVault.sol  (deployed on a local Hardhat blockchain)
    - stores each window's hash permanently
    - exposes getWindow(windowId) to read back a stored hash
        |
        v
  verify_onchain.py
    - re-reads current logs.txt
    - recomputes each window's hash from the current content
    - calls getWindow() on the contract to fetch the trusted hash
    - compares: match -> Intact, mismatch -> Tampered, no local data but
      on-chain record exists -> Missing
```

## Why Chaining Matters

Each window's hash is not just a hash of that window's logs — it includes the
previous window's hash as an input:

```
window_hash(n) = SHA256(window_hash(n-1) + logs_in_window_n)
```

This means tampering with an old window changes that window's hash, which
would change every window's hash computed after it, if they were all
recomputed from scratch. Since each window is anchored separately and
immutably on-chain the moment it's sealed, an attacker cannot retroactively
patch the chain without the earlier anchored hashes already being
permanent, mismatched, on-chain evidence of exactly when the tampering
happened.

## Why the Blockchain Matters

If the hash chain were only stored in a local file (`hash_chain.json`)
sitting next to the logs it protects, an attacker with admin access could
edit both the logs and the hash file together, and nothing would catch it.
Writing each window's hash to a blockchain moves the trusted copy outside
the reach of anyone with access to the log server itself. The contract's
`require(!windows[windowId].exists)` check means a hash, once anchored,
can never be overwritten — not even by the contract's deployer.

## Components

| Component | Technology | Purpose |
|---|---|---|
| Log generation | Python + Faker | Produces realistic synthetic security events |
| Hashing | Python hashlib (SHA-256) | Cryptographic fingerprint per window |
| Chaining | Custom logic in hash_windows.py | Links windows so tampering breaks the chain |
| Smart contract | Solidity | Immutable on-chain storage of window hashes |
| Blockchain dev network | Hardhat | Local Ethereum-compatible chain for development |
| Chain interaction | Python (raw JSON-RPC / web3.py) | Deploys contract, anchors hashes, reads them back |
| Verification | Python | Independently recomputes and compares hashes |
