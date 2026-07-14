# BNS Contracts

First EVM implementation of the BNS registry described in
`../../../doc/BNS/BNS 智能合约接口设计.md`.

## Layout

- `src/Bns.sol`: UUPS implementation and selector router.
- `src/BnsCore.sol`: shared proxy storage layout and internal business helpers.
- `src/BnsTypes.sol`, `src/BnsEvents.sol`, `src/IBns.sol`: protocol types,
  events, and the aggregated public ABI.
- `src/Bns*Facet.sol`: registration, atomic mutation, name, document, authority,
  alias/payment, and resolver implementations executed with `delegatecall`.
- `test/*.sol`: Hardhat Solidity tests for authorization, guards, documents, events,
  fuzz properties and invariants.
- `hardhat-scripts/facet-manifest.json`: reviewed selector-to-facet assignment used by
  tests and deployment.
- `hardhat-scripts/check-facets.mjs`: runtime-size, selector coverage/collision, and
  shared-storage-layout checks over Hardhat artifacts.
- `hardhat-scripts/smoke.ts`: deploys a fresh Router/Facet proxy to Anvil and runs the
  register/publish/resolve smoke flow.
- `scripts/anvil.sh`: starts a persistent local Anvil chain.

## Contract Tests

Hardhat 3 runs the existing Solidity test contracts, fuzz cases and invariants on
its in-process EDR chain. Contract tests do not require Foundry or a separately
running Anvil process. Node.js 22.13 or newer is required.

```bash
cd src/apps/bns
npm install
npm test
```

Compile the same Solidity source, validate facet boundaries, and synchronize the
committed ABI used by Backend/deployment tooling:

```bash
cd src/apps/bns
npm run compile
npm run abi:check
```

`npm run compile` checks all 28 routed selectors, the EIP-170 limit, and the complete
Solidity storage layout shared by Router and facets. It writes the stable aggregate
JSON ABI and the Solidity source used for Rust code generation to
`../../components/bns-evm/abi/`. The aggregate starts with `IBns`, then merges the
complete Router/facet artifacts so inherited UUPS/Ownable events and errors are not
lost. Its generated Solidity form takes calls/events/errors and struct shapes from the
JSON ABI, while restoring enum members from the compiler AST in Hardhat build-info;
standard JSON ABI retains enum names but cannot represent their variants. Hardhat
artifacts and cache remain local.

## Upgradeability

The public deployment uses the OpenZeppelin UUPS pattern:

- `Bns` inherits `Initializable`, `OwnableUpgradeable`, and `UUPSUpgradeable`;
- the implementation constructor disables initializers;
- OpenZeppelin Hardhat Upgrades deploys an ERC-1967 proxy and atomically calls
  `initialize(deployer)`;
- only `owner()` (the configured upgrade admin) can call `upgradeToAndCall`;
- the UUPS implementation routes business selectors to separately deployed facets;
- facets execute with `delegatecall`, so business state, `msg.sender`, `address(this)`,
  events, and the global log root all remain attached to the proxy;
- business state uses one shared `BnsCore` layout and reserves a storage gap for
  future versions;
- the selector table uses the independent
  `keccak256("buckyos.bns.router.storage.v1")` storage namespace.

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

`hardhat-scripts/deploy.ts` is network-independent and has no chain allowlist or
extra deployment-confirmation environment variable. Select any EVM-compatible network
configured in `hardhat.config.ts` with Hardhat's `--network` option; the script reads
the actual chain ID from its RPC for the deployment record:

```bash
cd src/apps/bns
npm run deploy -- --network anvil
```

For local automation, `deploy:local` reuses the same UUPS/facet deployment code but
refuses RPC URLs whose host is not exactly `localhost` or `127.0.0.1`. Its stdout is
compatible with `forge create --json` (`deployer`, `deployedTo`, and
`transactionHash`), while deployment progress is written to stderr:

```bash
BNS_ANVIL_RPC_URL=http://127.0.0.1:8545 \
BNS_ANVIL_PRIVATE_KEY=0x... \
npm run --silent deploy:local
```

For OP Mainnet, the existing `opMainnet` config reads its RPC URL and deployment key
from the environment. Its convenience command is:

```bash
cd src/apps/bns
BNS_OP_MAINNET_RPC_URL=https://your-op-mainnet-rpc \
BNS_DEPLOYER_PRIVATE_KEY=0x... \
npm run deploy:op-mainnet
```

The script uses Ethers' default confirmation count when waiting for the proxy
deployment transaction. Before deployment, it checks that:

- `src/`, Hardhat config, package manifests, lockfile, and the deployment script are
  all tracked and clean at `HEAD`;
- the deployment output does not already exist;
- OpenZeppelin's upgrade-safety validation accepts the UUPS implementation;
- the facet manifest covers the complete business ABI without selector collisions,
  every facet shares the Router's storage layout, and all runtime sizes are deployable.

OpenZeppelin Hardhat Upgrades owns router implementation/proxy deployment,
initialization, ERC-1967 lookup, and its per-network manifest. The deployment script
also deploys every facet, rejects duplicate selectors or facet runtime larger than
24,576 bytes, installs the selector manifest, and reads every selector back from the
proxy. It verifies the on-chain upgrade admin before writing
`deployments/<network-name>.json` (`op-mainnet.json` for the `opMainnet` config).
The record contains at least:

- `deployedAt`;
- `deploymentCommitHash`;
- `proxyAddress`;
- `implementationAddress`;
- every facet address, runtime size, selectors, deployment transaction and block;
- the selector-configuration transaction;
- network and chain ID, deployer, upgrade admin, router bytecode size, proxy
  transaction hash, and block number.

The proxy, implementation, and facet addresses are also printed to the console. The
private key is only read from the selected Hardhat network configuration and is never
printed or written to the deployment record. OpenZeppelin also writes a network manifest
under `.openzeppelin/`; commit manifests for persistent networks because later
upgrade validation and implementation reuse depend on them. Ephemeral
manifests for the common local chain IDs 1337 and 31337 are ignored.

### Runtime bytecode sizes

With Solidity 0.8.24, `viaIR=true`, and optimizer `runs=20`, the deployable production
contracts are:

| Contract | Runtime bytes |
| --- | ---: |
| `Bns` UUPS Router | 4,562 |
| `BnsResolverFacet` | 9,882 |
| `BnsRegistrationFacet` | 17,244 |
| `BnsAtomicMutationFacet` | 19,145 |
| `BnsNameFacet` | 9,857 |
| `BnsAuthorityFacet` | 6,670 |
| `BnsDocumentFacet` | 13,835 |
| `BnsAliasPaymentFacet` | 10,321 |

Every implementation is below the EIP-170 24,576-byte runtime limit. The largest
facet retains 5,431 bytes of upgrade headroom. The proxy remains the only address used
by clients and indexers.

## Local Anvil Chain

Anvil remains the persistent local development chain. Hardhat connects to its JSON-RPC
endpoint for deployment and smoke execution; Hardhat Node is not involved. Install
Foundry for the `anvil` binary only—the local contract smoke no longer uses `forge`.

```bash
curl -L https://foundry.paradigm.xyz | bash
foundryup
```

Start the persistent chain:

```bash
cd src/apps/bns
./scripts/anvil.sh
```

In another terminal, run the complete deployment and contract smoke flow:

```bash
cd src/apps/bns
npm run smoke:anvil
```

Override the endpoint when Anvil is not listening on the default
`http://127.0.0.1:8545`. A private key is optional because Hardhat otherwise uses an
unlocked Anvil account:

```bash
cd src/apps/bns
BNS_ANVIL_RPC_URL=http://127.0.0.1:9545 \
BNS_ANVIL_PRIVATE_KEY=0x... \
npm run smoke:anvil
```

Each smoke run deploys seven facets plus a fresh UUPS Router proxy, installs all 28
business selectors, registers `alice`, publishes its inline `owner` document, and
resolves the active version from the proxy. Addresses and each successful phase are
printed to the console; no separate local deployment step or record is required.

## DV Integration Environment

See `doc/SN/SN-测试计划.md` §5 for the full flow. The scripted path keeps Anvil for
persistent local chain state, but deployment now uses the same Hardhat UUPS/facet code
as production and chain inspection uses JSON-RPC directly. It therefore requires the
Foundry installation only for the `anvil` binary, not `forge` or `cast`.

**(A) Self-contained Rust e2e** (recommended, CI-able). Spawns its own anvil + deploys
in-process; `#[ignore]` by default, skipped gracefully when Foundry is absent:

```bash
cd src
cargo test -p bns-client --test e2e_anvil -- --ignored
```

**(B) Scripted DV environment + smoke.** `dv-up.sh` brings up Anvil, deploys the BNS
UUPS proxy and all facets through `deploy:local`, and runs `bns-dv serve` (indexer
`sync_once` poll loop + contract server over a shared SQLite projection), then writes
`dv-env.json`:

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

The V1 public ABI remains available at one proxy address, while its implementation is
split across deployable facets. Backend and Indexer code use the aggregated `IBns` ABI
and do not need facet addresses for normal protocol calls or event synchronization.
