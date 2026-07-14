# BNS Contracts

First EVM implementation of the BNS registry described in
`../../../doc/BNS/BNS 智能合约接口设计.md`.

## Layout

- `src/Bns.sol`: registry contract and protocol structs.
- `src/BnsProxy.sol`: ERC-1967 proxy used by the UUPS deployment.
- `test/*.sol`: Hardhat Solidity tests for authorization, guards, documents, events,
  fuzz properties and invariants.
- `script/Smoke.s.sol`: deploys a fresh contract to a local chain and runs a minimal write flow.
- `scripts/anvil.sh`: starts a persistent local Anvil chain.
- `scripts/deploy.sh`: legacy local-chain direct deployment used by the existing DV flow.

## Contract Tests

Hardhat 3 runs the existing Solidity test contracts, fuzz cases and invariants on
its in-process EDR chain. Contract tests do not require Foundry or a separately
running Anvil process. Node.js 22.13 or newer is required.

```bash
cd src/apps/bns
npm install
npm test
```

Compile the same Solidity source and synchronize the committed ABI used by
Backend/deployment tooling:

```bash
cd src/apps/bns
npm run compile
npm run abi:check
```

`npm run compile` writes only the stable ABI array to
`../../components/bns-evm/abi/Bns.json`. Hardhat artifacts and cache remain local.

## Upgradeability

The public deployment uses the OpenZeppelin UUPS pattern:

- `Bns` inherits `Initializable`, `OwnableUpgradeable`, and `UUPSUpgradeable`;
- the implementation constructor disables initializers;
- the `BnsProxy` constructor atomically calls `initialize(upgradeAdmin)`;
- only `owner()` (the configured upgrade admin) can call `upgradeToAndCall`;
- business state is stored in the proxy and the v1 layout reserves a storage gap for
  future implementation versions.

The upgrade admin should be a dedicated multisig or governance account, not the
deployment hot wallet. Clients and indexers must always use the proxy address.

## OP Mainnet Deployment

The production deployment script targets OP Mainnet chain ID 10 and requires an
explicit RPC URL, deployment key, upgrade admin, and confirmation guard:

```bash
cd src/apps/bns
BNS_OP_MAINNET_RPC_URL=https://your-op-mainnet-rpc \
BNS_DEPLOYER_PRIVATE_KEY=0x... \
BNS_UPGRADE_ADMIN=0x... \
BNS_DEPLOY_CONFIRMATION=OP_MAINNET \
npm run deploy:op-mainnet
```

`BNS_DEPLOY_CONFIRMATIONS` defaults to `2` and can be set to an integer from 1 to
64. Before sending either transaction, the script checks that:

- `src/`, Hardhat config, package manifests, lockfile, and the deployment script are
  all tracked and clean at `HEAD`;
- the selected Hardhat network is `opMainnet` and the RPC reports chain ID 10;
- the deployment output does not already exist;
- the implementation runtime bytecode is within the EIP-170 24,576-byte limit;
- `BNS_DEPLOY_CONFIRMATION` exactly matches `OP_MAINNET`.

The script deploys the implementation first, then an initialized ERC-1967 proxy. It
verifies the proxy implementation slot and the on-chain upgrade admin before writing
`deployments/op-mainnet.json`. The record contains at least:

- `deployedAt`;
- `deploymentCommitHash`;
- `proxyAddress`;
- `implementationAddress`;
- deployer, upgrade admin, bytecode size, transaction hashes, and block numbers.

The proxy and implementation addresses are also printed to the console. The private
key is only read by Hardhat through `BNS_DEPLOYER_PRIVATE_KEY` and is never printed or
written to the deployment record.

### Current deployment blocker

After the UUPS conversion, the optimized BNS implementation runtime bytecode is
41,079 bytes. OP Mainnet enforces the EIP-170 limit of 24,576 bytes, so the deployment
script currently stops before connecting a wallet or sending a transaction. Contract
splitting/size reduction is a separate prerequisite for the actual mainnet deployment;
changing proxy type would not remove this implementation-size limit.

## Local Anvil Chain

The current persistent DV chain and deployment scripts still use Foundry. Install
it when running those workflows; replacing Anvil is a separate migration step.

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Scripts that target an existing Anvil instance can use `npm run run:anvil -- <script>`;
override the default endpoint with `BNS_ANVIL_RPC_URL` and provide
`BNS_ANVIL_PRIVATE_KEY` only when the script needs an account.

Start a private chain:

```bash
cd src/apps/bns
./scripts/anvil.sh
```

Deploy in another terminal:

```bash
cd src/apps/bns
BNS_RPC_URL=http://127.0.0.1:8545 \
BNS_DEPLOYER_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
./scripts/deploy.sh
```

Run an on-chain smoke flow against Anvil:

```bash
cd src/apps/bns
BNS_RPC_URL=http://127.0.0.1:8545 \
BNS_PRIVATE_KEY=0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80 \
forge script script/Smoke.s.sol:Smoke \
  --rpc-url "$BNS_RPC_URL" \
  --broadcast \
  --disable-code-size-limit
```

## DV Integration Environment (end-to-end)

See `doc/SN/SN-测试计划.md` §5. Two ways to exercise the full
`BNS(contract) <-> Indexer <-> Server <-> Client <-> Controller` path against a real
private chain (requires Foundry: `anvil`, `forge`, `cast`).

**(A) Self-contained Rust e2e** (recommended, CI-able). Spawns its own anvil + deploys
in-process; `#[ignore]` by default, skipped gracefully when Foundry is absent:

```bash
cd src
cargo test -p bns-client --test e2e_anvil -- --ignored
```

**(B) Scripted DV environment + smoke.** `dv-up.sh` brings up anvil, deploys `Bns.sol`,
and runs `bns-dv serve` (indexer `sync_once` poll loop + contract server over a shared
SQLite projection), then writes `dv-env.json`:

```bash
cd src/apps/bns
./scripts/dv-up.sh --fresh        # fresh chain + deploy + indexer/server (background)
./scripts/dv-smoke.sh             # register -> publish -> wait sync -> read (cross-layer)
./scripts/dv-down.sh              # stop services (anvil state persists for --resume)
./scripts/dv-up.sh --resume       # reuse anvil-state + contract + indexer cursor
./scripts/dv-smoke.sh             # cursor continues (no replay from 0)
./scripts/dv-down.sh --purge      # stop + remove persisted state
```

Use `dv-up.sh --keep-running` to run in the foreground for manual debugging.

## V1 Scope

Implemented:

- `registerName`, `applyMutations`, `renewName`, `transferName`, `setNameOwner`,
  `releaseName`, `setNamespacePolicy`
- `updateAuthorityKeys`, `setControllerPolicy`
- `publishDocument`, `revokeDocument`, `setDidAlias`, `setPaymentTarget`
- core query APIs from the interface design

Direct EVM calls keep `CallAuthority` in the ABI, but identity is not trusted from
that struct. The contract derives the concrete signer from `msg.sender` and checks it
against either the effective chain-account owner or a registered BNS authority key.
This is the intended signing boundary for the Anvil/private-chain V1.

The V1 contract intentionally keeps the full closed-loop interface in one contract, so
its bytecode is above the public-chain EIP-170 size limit. The Anvil script disables
that limit for the private-chain workflow. Before a public-chain deployment, split the
contract into facets/modules or move read-heavy helpers out of the write contract.
