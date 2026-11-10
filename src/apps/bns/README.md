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
- `hardhat-scripts/smoke.ts`: selects local deployment or an explicit external proxy.
- `hardhat-scripts/smoke-common.ts`: fixtures, confirmed transactions, exact custom-error
  checks, receipt/event validation and interface coverage accounting.
- `hardhat-scripts/smoke-test.ts`: business scenarios shared by every network.
- `hardhat-scripts/smoke-time.ts`, `smoke-admin.ts`: isolated local time and proxy-management scenarios.
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

Compile the Solidity source, validate facet boundaries, and generate the aggregate
binding inside the contract project:

```bash
cd src/apps/bns
npm run compile:sync
# generated: bindings/BnsBindings.sol
```

`npm run compile:sync` checks all 28 routed selectors, the EIP-170 limit, and the complete
Solidity storage layout shared by Router and facets. The binding generator starts with
`IBns`, merges the complete Router/facet artifact ABIs so inherited UUPS/Ownable events
and errors are not lost, and restores enum members from the compiler AST in Hardhat
build-info. Standard JSON ABI retains enum names but cannot represent their variants.

Generation and cross-project synchronization remain separate underlying actions. `compile`
writes only `bindings/BnsBindings.sol` under this contract project and never modifies
a Backend repository. In the current monorepo, explicitly copy that generated file to
`bns-evm` with:

```bash
npm run abi:sync
npm run abi:check
```

The default monorepo workflow uses `npm run compile:sync` to perform compile, generation,
and synchronization in one command. If BNSContract later becomes a submodule of a
separate Backend repository, the Backend should run `npm run compile` in the submodule
and copy `bindings/BnsBindings.sol` with its own build script; the contract project does
not need to know the Backend layout. Hardhat artifacts, cache, and generated local
bindings remain ignored build outputs. `bns-evm` does not consume a JSON ABI, so no
`Bns.json` copy is maintained.

## Owner validation and authority limits (#185)

Registration and owner/asset transfers validate only the changed name's owner
path. `BnsName(x)` terminates at x's authority set; it does not recurse into x's
semantic owner. These writes and authority updates no longer scan all names, so
an unrelated expired/released authority cannot block another user's writes.

Once a lineage has a persisted nonzero authentication-key count, every successful
authority update must leave at least one currently active authentication key.
This applies even without dependants. Rotate keys in one batch, revoking the old
key and installing the replacement together. The previous persisted count is
used even after keys expire; it is a snapshot, not a live count. Natural key
expiry and authority-name expiry/release can still disable dependants. This rule
does not add a recovery path. Recovery/document-only sets that have always had a
zero authentication count remain supported, and a fresh lineage starts afresh.

Each authority-update array is limited to 32 entries, including the standalone
`updateAuthorityKeys` entrypoint. Historical KIDs are **not capped**: authority-root
recomputation still costs O(K) in the current lineage's recorded KIDs, including
revoked keys. Before this history becomes large, measure the worst-case mutation
against the selected chain's transaction/block gas limits and revisit the cap.

The #185 changes preserve storage layout, ABI, events, and authority-root encoding.
They are intended for the next fresh test-chain deployment; no mainnet deployment
or migration is part of this change. Existing clients and bns_dv need no protocol
changes. A new chain/proxy still requires the usual backend/SN network-address
configuration and fresh indexer state.

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

## Contract Smoke Tests

The smoke suite exercises the deployed production Router/facets through their public
ABI. It supplements the Solidity unit/fuzz tests; interface coverage means successful
calls to each interface, not complete branch coverage. Each run uses a random
`smoke...` prefix and prints its account, proxy, scenario results and transaction hashes.
Missing successful coverage of any of the 28 business interfaces in
`facet-manifest.json` fails the run. Negative cases require the exact custom error;
RPC/transport failures cannot count as expected contract reverts.

### Local Hardhat chain

Run the complete deployment + business + time + administration suite on a fresh
Hardhat 3 in-process EDR chain, with no Anvil installation or separate node process:

```bash
cd src/apps/bns
npm run smoke:local
```

To inspect the same flow through a standalone Hardhat JSON-RPC node, use two terminals:

```bash
# Terminal 1
npm run node:local
# Terminal 2
npm run smoke:localhost
# Optional custom port: npm run node:local -- --port 9545
# BNS_LOCAL_RPC_URL=http://127.0.0.1:9545 npm run smoke:localhost
```

`localhost` must resolve to a loopback URL and identify itself as Hardhat before the
script deploys or enables time/admin operations. Every simulated network is also
local. Local runs always deploy fresh facets and a proxy, ignoring
`BNS_CONTRACT_ADDRESS`. Time/admin scenarios use snapshots restored in `finally`,
including on failure, so those scenarios restore the node's previous timestamp and
state. Use a dedicated node without concurrent writers; snapshot restoration also
reverts transactions submitted by other clients during a scenario.

### Deployed contracts (USDB and other networks)

Select a network from `hardhat.config.ts` and explicitly supply its deployed **BNS
proxy** address. The address is required even when a deployment record exists:

```bash
cd src/apps/bns
BNS_CONTRACT_ADDRESS=0xYourDeployedBnsProxyAddress \
npm run smoke -- --network usdbtest
```

Other HTTP networks never deploy contracts. Missing/invalid addresses, no contract
code, missing signer, failed receipts, assertion failures or unexpected reverts all
exit nonzero. The selected network's first signer needs funds for the test
transactions (including one intentionally reverted batch transaction); no second funded account or deployment-admin privilege is required.
Each external run leaves its test names/documents and a log checkpoint on-chain.
Time manipulation and proxy administration are explicitly reported as `[SKIP]`.

### Coverage contract

| Area | All networks | Additional local Hardhat checks |
| --- | --- | --- |
| Router/read API | Constants, all selector routes have code, owner/version, principal encoding, absent/invalid names, reinitialization/proxy UUID rejection | Facet replacement/removal/restoration, protected selectors, admin access, UUPS upgrade with state preservation, ownership transfer/renunciation |
| Registration/names | Initial documents, duplicate registration, ownership, renewal, child inheritance, parent-sequence guard, namespace policy | Expiry immediately before/at boundary, expired writes/parent rejection, renewal past grace and document recovery |
| Documents | Inline hash/byte readback, 4096-byte boundary, oversized/hash/type rejection, external URI, versions/history, revocation and republication | Independent document expiry boundary and expired purchase context |
| Authority/ownership | Keys and roots, semantic BNS owner, rotation, revoked/last-key rejection, atomic asset/document transfer, fallback restoration | Key validity start/end boundaries, expiry safety latch and recovery |
| Controllers | Scoped/wildcard rules, all five permission bits, wrong actor, missing permission, policy removal | Validity start/end boundaries |
| Atomic mutations | Combined keys/documents/IAT floor, one name-sequence increment, empty/duplicate/oversized batches, mined revert and rollback, monotonic IAT floor | Same business checks |
| Lifecycle | Release, re-registration resets current lineage/alias/keys/controller policy, historical docs retained, permanent tombstone | Same business checks |
| Events/checkpoint | Business events, receipt-local protocol sequence/root continuity, actor/proxy, checkpoint root/sequence/timestamp | Exact mining of five blocks |

Local time checks use `hardhat_mine`, `evm_setNextBlockTimestamp`, `evm_mine` and
snapshot/revert RPCs described in the [Hardhat JSON-RPC reference](https://hardhat.org/docs/reference/json-rpc-methods).
No sleeps or waits for real expiration are required. External networks receive no
time, mining, snapshot or admin RPCs. Shared global-log checks use the current
transaction's events rather than assuming exclusive ownership of the whole chain.

### Legacy Anvil path

`npm run smoke:anvil` remains available for existing local automation. It deploys a
fresh proxy and runs the expanded business suite, with time/admin scenarios skipped.
Start Anvil with `./scripts/anvil.sh`; override its RPC/account with
`BNS_ANVIL_RPC_URL` / `BNS_ANVIL_PRIVATE_KEY`. The DV/Rust integration environment
below continues to use Anvil independently of the contract smoke default.

## DV Integration Environment

See `doc/SN/SN-测试计划.md` §5 for the full flow. The scripted path keeps Anvil for
persistent local chain state, but deployment now uses the same Hardhat UUPS/facet code
as production and chain inspection uses JSON-RPC directly. It therefore requires the
Foundry installation only for the `anvil` binary, not `forge` or `cast`.

**(A) Self-contained Rust e2e** (recommended, CI-able). Spawns its own Anvil and deploys
the UUPS proxy/facets through the shared Hardhat path; `#[ignore]` by default, skipped
gracefully when `anvil`, `node`, or `npm` is absent:

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
