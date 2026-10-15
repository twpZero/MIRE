// Run with: npm test
const test = require('node:test');
const assert = require('node:assert');
const M = require('../js/model.js');
const D = require('../js/defaults.js');
const IO = require('../js/io.js');

function tiny() {
  return IO.normalize({
    actors: ['X', 'Y'],
    zones: ['Z1', 'Z2'],
    attacks: [
      { id: 'a1', name: 'Phishing', impact: 4, probability: 5, means: 5, actors: { X: 1, Y: 0 } },
      { id: 'a2', name: 'USB', impact: 3, probability: 2, means: 3, actors: { X: 0, Y: 1 } },
    ],
    defenses: [{ id: 'd1', name: 'Mail GW' }, { id: 'd2', name: 'EDR' }],
    layers: [{
      id: 'L1', name: 'Base', values: {
        d1: { cost: 2, difficulty: 2, missing: 2, lack: 2, zones: { Z1: 1, Z2: 0 } },
        d2: { cost: 4, difficulty: 3, missing: 2, lack: 1, zones: { Z1: 4, Z2: 4 } },
      },
    }, {
      id: 'L2', name: 'Site B', values: {
        d1: { cost: 3, difficulty: 1, missing: 2, lack: 2, zones: { Z1: 2, Z2: 1 } },
        d2: { cost: 4, difficulty: 3, missing: 2, lack: 1, zones: { Z1: 0, Z2: 4 } },
      },
    }],
    mapping: { a1: { d1: 1, d2: 1 }, a2: {} },
  });
}

test('attack score and actor weight', () => {
  const s = tiny();
  assert.strictEqual(M.attackScore(s.attacks[0]), 100);
  assert.strictEqual(M.actorWeight(s.attacks[0], []), 1);
  assert.strictEqual(M.actorWeight(s.attacks[0], ['Y']), 0);
  assert.strictEqual(M.actorWeight(s.attacks[0], ['X', 'Y']), 1); // adding actors = max
});

test('MIRE = A × w × min D, unmitigated = D max', () => {
  const s = tiny();
  const r = M.computeAttacks(s, { actors: [], zones: ['Z1'], layerIds: ['L1'] });
  // d1 in Z1: 2*2*2*2*1 = 16, d2: 4*3*2*1*4 = 96 → min 16
  assert.strictEqual(r.rows[0].D, 16);
  assert.strictEqual(r.rows[0].by, 'd1');
  assert.strictEqual(r.rows[0].mire, 1600);
  assert.strictEqual(r.rows[1].D, 3125);
  assert.strictEqual(r.rows[1].mire, 18 * 3125);
});

test('several zones = mean, weakest zone reported; CERT view ignores cost and difficulty', () => {
  const s = tiny();
  const r = M.computeAttacks(s, { actors: [], zones: ['Z1', 'Z2'], layerIds: ['L1'] });
  assert.strictEqual(r.rows[0].zone, 'Z2'); // d1 absent in Z2 → d2 = 96
  assert.strictEqual(r.rows[0].by, 'd2');
  assert.strictEqual(r.rows[0].D, (16 + 96) / 2);
  assert.strictEqual(r.rows[0].mire, 100 * (16 + 96) / 2);
  assert.strictEqual(r.rows[1].coveredZones, 0);
  const c = M.computeAttacks(s, { actors: [], zones: ['Z1'], layerIds: ['L1'], cert: true });
  assert.strictEqual(c.rows[0].D, 4); // missing*lack*zone = 2*2*1
  assert.strictEqual(c.rows[1].D, 125);
});

test('multi-layer merge takes the weakest setting per line', () => {
  const s = tiny();
  const m = M.mergeLayers(s, ['L1', 'L2']);
  assert.deepStrictEqual(m.d1, { cost: 3, difficulty: 2, missing: 2, lack: 2, zones: { Z1: 2, Z2: 0 } });
  assert.deepStrictEqual(m.d2.zones, { Z1: 0, Z2: 4 });
});

test('defense ranking: unique reduction and blocking', () => {
  const s = tiny();
  const opts = { actors: [], zones: ['Z1'], layerIds: ['L1'] };
  const d = M.computeDefenses(s, opts);
  const gw = d.find((x) => x.id === 'd1');
  // without d1, a1 falls back to d2: 100*96 vs 100*16
  assert.strictEqual(gw.unique, 100 * 96 - 100 * 16);
  assert.ok(Math.abs(gw.blocking - (100 * (3125 - 16)) / 3125) < 1e-9);
});

test('default dataset is consistent', () => {
  const raw = D.build();
  const s = IO.normalize(raw);
  for (const [aid, row] of Object.entries(raw.mapping)) {
    for (const did of Object.keys(row)) assert.ok(s.defenses.find((d) => d.id === did), `${aid} → unknown ${did}`);
  }
  assert.strictEqual(Object.keys(s.mapping).length, s.attacks.length);
  const res = M.compute(s, { actors: [], layerIds: ['l_base'] });
  assert.strictEqual(res.attacks.rows.length, s.attacks.length);
  const x = M.computeAttacks(s, { actors: [], layerIds: ['l_p1'] });
  assert.ok(x.total < res.attacks.total, 'Project X lowers residual exposure');
});

test('CSV and table round trip', () => {
  const s = IO.normalize(D.build());
  const h = IO.headers(s);
  const parse = (rows, hd) => IO.csvParse(IO.csvStringify(rows, hd));
  const tables = {
    attacks: parse(IO.attacksTable(s), h.attacks),
    defenses: parse(IO.defensesTable(s), h.defenses),
    mapping: parse(IO.mappingTable(s), h.mapping),
  };
  assert.strictEqual(IO.classify(tables.attacks), 'attacks');
  assert.strictEqual(IO.classify(tables.defenses), 'defenses');
  assert.strictEqual(IO.classify(tables.mapping), 'mapping');
  const back = IO.applyTables(IO.normalize({}), tables, 'replace');
  assert.strictEqual(back.attacks.length, s.attacks.length);
  assert.strictEqual(back.layers.length, s.layers.length);
  const opts = (st) => ({ actors: ['FIN12'], layerIds: [st.layers[1].id] });
  assert.strictEqual(M.computeAttacks(back, opts(back)).total, M.computeAttacks(s, opts(s)).total);
});

test('import defense file as a new layer', () => {
  const s = IO.normalize(D.build());
  const rows = [{ Defense: 'Perimeter firewall', Cost: 1, 'Operational Difficulty': 1, 'Missing Coverage': 1, 'Lack of Efficiency': 1, Perimeter: 'Deny', OT: 'Detect' }];
  const next = IO.applyTables(s, { defenses: rows }, 'layer', 'Plant');
  assert.strictEqual(next.layers.length, s.layers.length + 1);
  assert.ok(next.zones.includes('OT'));
  const l = next.layers[next.layers.length - 1];
  assert.strictEqual(l.name, 'Plant');
  assert.strictEqual(l.values.d_fw.zones.OT, 5);
  assert.strictEqual(l.values.d_fw.zones.Perimeter, 1);
  assert.strictEqual(next.attacks.length, s.attacks.length);
});
