/*
 * MIRE — Measure Impact of Residual Exposure
 * Pure computation model (no DOM). Works in the browser (window.MIRE) and in Node (require).
 *
 *   A(attack)        = Impact × Probability × Means                       (1 … 125)
 *   w(attack)        = max over selected actors of actor flag             (0 … 1, 1 when no actor selected)
 *   D(attack, defense, zone) = Cost × Difficulty × Lack × Missing(zone) × Action(attack, defense)   (1 … 3125)
 *   D_cert                   = Lack × Missing(zone) × Action(attack, defense)                       (1 … 125)  — CERT view
 *   D(attack, zone)  = min D over defenses mapped to the attack and deployed in the zone
 *                      (D_max when nothing covers it: unmitigated)
 *   MIRE(attack)     = A × w × D(attack, zone)        — mean over zones when several zones are selected
 *
 *   Action (mapping cell): 1 Deny · 2 Defer · 3 Degrade · 4 Disrupt · 5 Detect · 0 = no effect on this attack.
 *   Missing (zone cell):   0 fully covered … 4 mostly missing · 5 = not deployed in the zone (maximum risk).
 *   Adding actors = max, adding defenses = min, merging defense layers = weakest value per line.
 */
(function (root, factory) {
  const M = factory();
  if (typeof module === 'object' && module.exports) module.exports = M;
  else root.MIRE = M;
})(typeof self !== 'undefined' ? self : this, function () {
  'use strict';

  const LEVELS = [
    { v: 1, name: 'Deny' },
    { v: 2, name: 'Defer' },
    { v: 3, name: 'Degrade' },
    { v: 4, name: 'Disrupt' },
    { v: 5, name: 'Detect' },
  ];
  const A_MAX = 125;
  const FEAS_FIELDS = ['cost', 'difficulty', 'lack'];
  const NOT_DEPLOYED = 5;

  function num(x, d = 0) {
    const n = Number(x);
    return Number.isFinite(n) ? n : d;
  }

  function attackScore(a) {
    return num(a.impact) * num(a.probability) * num(a.means);
  }

  function actorWeight(a, actors) {
    if (!actors || !actors.length) return 1;
    let w = 0;
    for (const x of actors) w = Math.max(w, num(a.actors && a.actors[x]));
    return w;
  }

  function dMax(cert) {
    return cert ? 125 : 3125;
  }

  function feasibility(v, cert) {
    if (!v) return 0;
    return cert ? num(v.lack) : num(v.cost) * num(v.difficulty) * num(v.lack);
  }

  /**
   * Residual score of one defense against one attack in one zone,
   * or null when the defense is not deployed there (missing = 5) or has no effect on the attack.
   */
  function defenseScore(v, zone, cert, action = 1) {
    if (!v || !(num(action) > 0)) return null;
    const z = Math.max(0, num(v.zones && v.zones[zone], NOT_DEPLOYED));
    if (z >= NOT_DEPLOYED) return null;
    return feasibility(v, cert) * z * num(action);
  }

  /** Multi-layer: for each defense line keep the weakest setting across the given layers. */
  function mergeLayers(state, layerIds) {
    const layers = state.layers.filter((l) => layerIds.includes(l.id));
    if (!layers.length) return {};
    if (layers.length === 1) return layers[0].values;
    const out = {};
    for (const d of state.defenses) {
      const vs = layers.map((l) => l.values[d.id]);
      const m = { zones: {} };
      for (const f of FEAS_FIELDS) m[f] = Math.max(...vs.map((v) => num(v && v[f], 5)));
      for (const z of state.zones) {
        m.zones[z] = Math.max(...vs.map((v) => num(v && v.zones && v.zones[z], NOT_DEPLOYED)));
      }
      out[d.id] = m;
    }
    return out;
  }

  /** [[defenseId, action level], …] for the defenses mapped to an attack. */
  function mappedDefenses(state, attackId) {
    const row = state.mapping[attackId] || {};
    return Object.keys(row).filter((k) => num(row[k]) > 0).map((k) => [k, num(row[k])]);
  }

  /**
   * opts: { actors: string[], zones: string[], layerIds: string[], cert: bool, exclude?: defenseId, values?: merged }
   */
  function computeAttacks(state, opts) {
    const cert = !!opts.cert;
    const DM = dMax(cert);
    const zones = opts.zones && opts.zones.length ? opts.zones : state.zones;
    const values = opts.values || mergeLayers(state, opts.layerIds || []);
    const rows = [];
    let total = 0;
    for (const a of state.attacks) {
      const A = attackScore(a);
      const w = actorWeight(a, opts.actors);
      const mapped = mappedDefenses(state, a.id).filter(([d]) => d !== opts.exclude);
      const perZone = {};
      let worst = null;
      let sumMire = 0;
      let sumD = 0;
      let coveredZones = 0;
      for (const z of zones) {
        let best = DM;
        let by = null;
        for (const [did, action] of mapped) {
          const s = defenseScore(values[did], z, cert, action);
          if (s !== null && s < best) {
            best = s;
            by = did;
          }
        }
        const mire = A * w * best;
        perZone[z] = { D: best, by, mire, norm: (100 * mire) / (A_MAX * DM) };
        sumMire += mire;
        sumD += best;
        if (by) coveredZones++;
        if (!worst || best > worst.D) worst = { zone: z, ...perZone[z] };
      }
      const n = zones.length || 1;
      const mire = zones.length ? sumMire / n : A * w * DM;
      const D = zones.length ? sumD / n : DM;
      rows.push({
        id: a.id, attack: a, A, w, mapped: mapped.length, perZone, coveredZones,
        zone: worst ? worst.zone : null, by: worst ? worst.by : null,
        D, mire, norm: (100 * mire) / (A_MAX * DM),
      });
      total += mire;
    }
    return { rows, total, max: A_MAX * DM * state.attacks.length, dMax: DM, zones, values };
  }

  function computeDefenses(state, opts, base) {
    base = base || computeAttacks(state, opts);
    const cert = !!opts.cert;
    const DM = base.dMax;
    const out = [];
    for (const d of state.defenses) {
      let covered = 0;
      let blocking = 0;
      const v = base.values[d.id];
      for (const r of base.rows) {
        const row = state.mapping[r.id] || {};
        const action = num(row[d.id]);
        if (!(action > 0) || r.w <= 0) continue;
        covered++;
        for (const z of base.zones) {
          const s = defenseScore(v, z, cert, action);
          if (s !== null) blocking += (r.A * r.w * (DM - s)) / DM / base.zones.length;
        }
      }
      const without = computeAttacks(state, { ...opts, values: base.values, exclude: d.id });
      const deployed = base.zones.filter((z) => defenseScore(v, z, cert) !== null);
      out.push({
        id: d.id,
        defense: d,
        covered,
        deployed,
        feasibility: feasibility(v, cert),
        blocking,
        unique: without.total - base.total,
        bestFor: base.rows.filter((r) => r.by === d.id).length,
      });
    }
    return out;
  }

  function compute(state, opts) {
    const attacks = computeAttacks(state, opts);
    const defenses = computeDefenses(state, opts, attacks);
    return { attacks, defenses };
  }

  return {
    LEVELS,
    A_MAX,
    FEAS_FIELDS,
    NOT_DEPLOYED,
    num,
    attackScore,
    actorWeight,
    dMax,
    feasibility,
    defenseScore,
    mergeLayers,
    computeAttacks,
    computeDefenses,
    compute,
  };
});
