# BNS Contracts

First EVM implementation of the BNS registry described in
`../../../doc/BNS/BNS 智能合约接口设计.md`.

## Layout

- `src/Bns.sol`: registry contract and protocol structs.
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
- OpenZeppelin Hardhat Upgrades deploys an ERC-1967 proxy and atomically calls
  `initialize(deployer)`;
- only `owner()` (the configured upgrade admin) can call `upgradeToAndCall`;
- business state is stored in the proxy and the v1 layout reserves a storage gap for
  future implementation versions.

The deployment account becomes both the initial owner and the UUPS upgrade admin.
Ownership can be transferred later with `transferOwnership` if governance changes.
Clients and indexers must always use the proxy address. The deployment uses
`deployProxy(..., { kind: "uups" })`; future implementations should be checked and
deployed with `upgradeProxy` or `prepareUpgrade` from the same plugin.
The current implementation can be checked without deploying it:

```bash
npm run validate:upgrade
```

## Upgradeable Deployment

`hardhat-scripts/deploy.ts` is network-independent. Select any network configured in
`hardhat.config.ts` with Hardhat's `--network` option. The confirmation value is
derived from the selected Hardhat network name and the chain ID returned by its RPC:

```bash
cd src/apps/bns
BNS_DEPLOY_CONFIRMATION=anvil:31337 \
npm run deploy -- --network anvil
```

For OP Mainnet, the existing `opMainnet` config reads its RPC URL and deployment key
from the environment. Its convenience command is:

```bash
cd src/apps/bns
BNS_OP_MAINNET_RPC_URL=https://your-op-mainnet-rpc \
BNS_DEPLOYER_PRIVATE_KEY=0x... \
BNS_DEPLOY_CONFIRMATION=opMainnet:10 \
npm run deploy:op-mainnet
```

The script uses Ethers' default confirmation count when waiting for the proxy
deployment transaction. Before deployment, it checks that:

- `src/`, Hardhat config, package manifests, lockfile, and the deployment script are
  all tracked and clean at `HEAD`;
- the deployment output does not already exist;
- `BNS_DEPLOY_CONFIRMATION` exactly matches `<networkName>:<chainId>`;
- OpenZeppelin's upgrade-safety validation accepts the UUPS implementation.

OpenZeppelin Hardhat Upgrades owns implementation/proxy deployment, initialization,
ERC-1967 lookup, and its per-network manifest. The script verifies the on-chain
upgrade admin before writing `deployments/<network-name>.json` (`op-mainnet.json` for
the `opMainnet` config). The record contains at least:

- `deployedAt`;
- `deploymentCommitHash`;
- `proxyAddress`;
- `implementationAddress`;
- network and chain ID, deployer, upgrade admin, bytecode size, proxy transaction
  hash, and block number.

The proxy and implementation addresses are also printed to the console. The private
key is only read from the selected Hardhat network configuration and is never printed
or written to the deployment record. OpenZeppelin also writes a network manifest
under `.openzeppelin/`; commit manifests for persistent networks because later
upgrade validation and implementation reuse depend on them. Ephemeral
manifests for the common local chain IDs 1337 and 31337 are ignored.

### Current deployment blocker

After the UUPS conversion, the optimized BNS implementation runtime bytecode is
41,079 bytes. OP Mainnet enforces the EIP-170 limit of 24,576 bytes, so the current
implementation still cannot be deployed there. OpenZeppelin's deployment plugin does
not change that limit. Contract splitting/size reduction remains a separate
prerequisite for the actual mainnet deployment.

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
