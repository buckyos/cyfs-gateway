const BASE = 'https://bns.buckyos.ai'
const NAME = 'test-iobns-20260715-01'
const ADDR = '0x90f79bf6eb2c4f870365e785982e1f101e93b906'
let seq = 0
async function rpc(method, params) {
  const r = await fetch(`${BASE}/kapi/bns`, {
    method: 'POST', headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ method, params, sys: [++seq] }),
  })
  return await r.json()
}
async function did(path) {
  const r = await fetch(`${BASE}/1.0/identifiers/${path}`)
  return { httpStatus: r.status, body: await r.json() }
}
const out = {
  _note: `captured from ${BASE} — 真实响应，请勿手工编辑；用 scripts/capture-fixtures.mjs 重新抓取`,
  name: NAME,
  address: ADDR,
  krpc: {
    systemInfo: await rpc('system.info', {}),
    queryNameState: await rpc('name.query_state', { name: NAME }),
    queryNameStateMissing: await rpc('name.query_state', { name: 'definitely-not-registered-xyz' }),
    queryNameStateInvalid: await rpc('name.query_state', { name: 'BadName' }),
    resolveOwner: await rpc('name.resolve_owner', { name: NAME }),
    resolveOwnerMissing: await rpc('name.resolve_owner', { name: 'definitely-not-registered-xyz' }),
    getAuthoritySet: await rpc('authority.get_set', { name: NAME }),
    resolveDocument: await rpc('document.resolve', { name: NAME, doc_type: 'owner' }),
    resolveDocumentMissing: await rpc('document.resolve', { name: NAME, doc_type: 'nonexistent' }),
    getDocumentVersionMissing: await rpc('document.get_version', { name: NAME, doc_type: 'owner', version: 99 }),
    queryByAddr: await rpc('name.query_by_addr', { address: ADDR, cursor: null, limit: 10 }),
    queryByAddrBadLimit: await rpc('name.query_by_addr', { address: ADDR, cursor: null, limit: 5000 }),
    queryTxStateNotFound: await rpc('tx.query_state', { tx_hash: '0x' + '0'.repeat(63) + '1' }),
    listEvents: await rpc('events.list', { from_seq: 0, limit: 8 }),
    latestCheckpointEmpty: await rpc('checkpoint.latest', {}),
    unknownMethod: await rpc('no.such_method', {}),
    badParams: await rpc('name.query_state', {}),
  },
  didResolver: {
    answer: await did(`did:bns:${NAME}?type=owner`),
    missing: await did(`did:bns:${NAME}?type=nonexistent`),
    notApplicable: await did('did:web:example.com'),
    historical: await did(`did:bns:${NAME}?type=owner&iat=1784110660`),
  },
}
process.stdout.write(JSON.stringify(out, null, 2) + '\n')
