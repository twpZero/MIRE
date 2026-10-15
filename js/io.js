/*
 * MIRE import / export helpers — converts the state to flat tables (rows of objects) and back.
 * Tables are shared by the CSV and XLSX formats; JSON is the full state.
 */
(function (root, factory) {
  const IO = factory(root.MIRE || (typeof require === 'function' ? require('./model.js') : null));
  if (typeof module === 'object' && module.exports) module.exports = IO;
  else root.MIRE_IO = IO;
})(typeof self !== 'undefined' ? self : this, function (MIRE) {
  'use strict';

  const num = MIRE.num;
  const uid = (p) => p + Math.random().toString(36).slice(2, 10);
  const norm = (s) => String(s == null ? '' : s).trim().toLowerCase().replace(/[^a-z0-9]/g, '');

  const ATTACK_COLS = { attack: 'name', name: 'name', tactic: 'tactic', impact: 'impact', probability: 'probability', means: 'means' };
  const ATTACK_IGNORE = ['id', 'a', 'attackscore', 'score'];
  const DEFENSE_COLS = {
    layer: 'layer', defense: 'name', name: 'name', category: 'category', cost: 'cost',
    difficulty: 'difficulty', operationaldifficulty: 'difficulty', missing: 'missing', missingcoverage: 'missing',
    lack: 'lack', lackofefficiency: 'lack',
  };
  const DEFENSE_IGNORE = ['id', 'feasibility', 'd'];
  const LEVEL_BY_NAME = Object.fromEntries(MIRE.LEVELS.map((l) => [l.name.toLowerCase(), l.v]));

  const clamp = (x, lo, hi, d) => Math.min(hi, Math.max(lo, num(x, d)));
  const score15 = (x) => Math.round(clamp(x, 1, 5, 3));
  function zoneLevel(x) {
    if (x == null || x === '') return 0;
    const s = String(x).trim().toLowerCase();
    if (s in LEVEL_BY_NAME) return LEVEL_BY_NAME[s];
    const m = s.match(/^([0-5])/);
    return m ? Number(m[1]) : 0;
  }
  function uniqueName(base, taken) {
    const set = new Set(taken);
    if (!set.has(base)) return base;
    let i = 2;
    while (set.has(`${base} (${i})`)) i++;
    return `${base} (${i})`;
  }

  /* ---------------- CSV ---------------- */
  function csvParse(text) {
    text = String(text).replace(/^﻿/, '');
    const delim = detectDelimiter(text);
    const rows = [];
    let row = [];
    let field = '';
    let q = false;
    for (let i = 0; i < text.length; i++) {
      const c = text[i];
      if (q) {
        if (c === '"' && text[i + 1] === '"') { field += '"'; i++; }
        else if (c === '"') q = false;
        else field += c;
      } else if (c === '"') q = true;
      else if (c === delim) { row.push(field); field = ''; }
      else if (c === '\n' || c === '\r') {
        if (c === '\r' && text[i + 1] === '\n') i++;
        row.push(field); rows.push(row); row = []; field = '';
      } else field += c;
    }
    if (field !== '' || row.length) { row.push(field); rows.push(row); }
    const nonEmpty = rows.filter((r) => r.some((c) => c.trim() !== ''));
    if (!nonEmpty.length) return [];
    const header = nonEmpty[0].map((h) => h.trim());
    return nonEmpty.slice(1).map((r) => Object.fromEntries(header.map((h, i) => [h, r[i] == null ? '' : r[i]])));
  }
  function detectDelimiter(text) {
    const first = text.split(/\r?\n/)[0] || '';
    const counts = [',', ';', '\t'].map((d) => [d, first.split(d).length]);
    counts.sort((a, b) => b[1] - a[1]);
    return counts[0][0];
  }
  function csvStringify(rows, header) {
    header = header || (rows[0] ? Object.keys(rows[0]) : []);
    const esc = (v) => {
      const s = v == null ? '' : String(v);
      return /[",\n\r;]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
    };
    return [header.map(esc).join(','), ...rows.map((r) => header.map((h) => esc(r[h])).join(','))].join('\r\n') + '\r\n';
  }

  /* ---------------- state -> tables ---------------- */
  function attacksTable(state) {
    return state.attacks.map((a) => {
      const r = { Attack: a.name, Tactic: a.tactic, Impact: a.impact, Probability: a.probability, Means: a.means };
      for (const x of state.actors) r[x] = num(a.actors[x]);
      return r;
    });
  }
  function defensesTable(state, layerIds) {
    const out = [];
    for (const l of state.layers) {
      if (layerIds && !layerIds.includes(l.id)) continue;
      for (const d of state.defenses) {
        const v = l.values[d.id] || {};
        const r = {
          Layer: l.name, Defense: d.name, Category: d.category,
          Cost: v.cost, 'Operational Difficulty': v.difficulty, 'Missing Coverage': v.missing, 'Lack of Efficiency': v.lack,
        };
        for (const z of state.zones) r[z] = num(v.zones && v.zones[z]);
        out.push(r);
      }
    }
    return out;
  }
  function mappingTable(state) {
    return state.attacks.map((a) => {
      const r = { Attack: a.name };
      const row = state.mapping[a.id] || {};
      for (const d of state.defenses) r[d.name] = num(row[d.id]) > 0 ? 1 : 0;
      return r;
    });
  }
  function headers(state) {
    return {
      attacks: ['Attack', 'Tactic', 'Impact', 'Probability', 'Means', ...state.actors],
      defenses: ['Layer', 'Defense', 'Category', 'Cost', 'Operational Difficulty', 'Missing Coverage', 'Lack of Efficiency', ...state.zones],
      mapping: ['Attack', ...state.defenses.map((d) => d.name)],
    };
  }

  /* ---------------- tables -> state parts ---------------- */
  function classify(rows) {
    if (!rows.length) return null;
    const keys = Object.keys(rows[0]).map(norm);
    if (keys.includes('impact') || keys.includes('probability')) return 'attacks';
    if (keys.includes('cost') || keys.includes('lackofefficiency') || keys.includes('missingcoverage')) return 'defenses';
    if (keys[0] === 'attack' || keys[0] === 'name') return 'mapping';
    return null;
  }

  function parseAttacks(rows) {
    if (!rows.length) return { actors: [], attacks: [] };
    const cols = Object.keys(rows[0]);
    const actors = cols.filter((c) => !(norm(c) in ATTACK_COLS) && !ATTACK_IGNORE.includes(norm(c)) && c.trim() !== '');
    const nameCol = cols.find((c) => ATTACK_COLS[norm(c)] === 'name');
    const get = (r, field) => {
      const c = cols.find((k) => ATTACK_COLS[norm(k)] === field);
      return c ? r[c] : undefined;
    };
    const attacks = [];
    for (const r of rows) {
      const name = String(nameCol ? r[nameCol] : '').trim();
      if (!name) continue;
      attacks.push({
        id: uid('a_'),
        name: uniqueName(name, attacks.map((a) => a.name)),
        tactic: String(get(r, 'tactic') || '').trim(),
        impact: score15(get(r, 'impact')),
        probability: score15(get(r, 'probability')),
        means: score15(get(r, 'means')),
        actors: Object.fromEntries(actors.map((x) => [x, clamp(r[x], 0, 1, 0)])),
      });
    }
    return { actors, attacks };
  }

  /** Returns { zones, defenses: [{name, category}], layers: [{name, values: {defName: values}}] } */
  function parseDefenses(rows, defaultLayer) {
    if (!rows.length) return { zones: [], defenses: [], layers: [] };
    const cols = Object.keys(rows[0]);
    const zones = cols.filter((c) => !(norm(c) in DEFENSE_COLS) && !DEFENSE_IGNORE.includes(norm(c)) && c.trim() !== '');
    const col = (field) => cols.find((k) => DEFENSE_COLS[norm(k)] === field);
    const cName = col('name'), cLayer = col('layer'), cCat = col('category');
    const defenses = [];
    const layers = [];
    for (const r of rows) {
      const name = String(cName ? r[cName] : '').trim();
      if (!name) continue;
      const layerName = String((cLayer && r[cLayer]) || defaultLayer || 'Imported').trim();
      let layer = layers.find((l) => l.name === layerName);
      if (!layer) layers.push((layer = { name: layerName, values: {} }));
      if (!defenses.find((d) => d.name === name)) defenses.push({ name, category: String((cCat && r[cCat]) || '').trim() });
      layer.values[name] = {
        cost: score15(r[col('cost')]),
        difficulty: score15(r[col('difficulty')]),
        missing: score15(r[col('missing')]),
        lack: score15(r[col('lack')]),
        zones: Object.fromEntries(zones.map((z) => [z, zoneLevel(r[z])])),
      };
    }
    return { zones, defenses, layers };
  }

  /** Returns { attackName: { defenseName: 1 } } */
  function parseMapping(rows) {
    const out = {};
    if (!rows.length) return out;
    const cols = Object.keys(rows[0]);
    const nameCol = cols[0];
    for (const r of rows) {
      const name = String(r[nameCol] || '').trim();
      if (!name) continue;
      out[name] = {};
      for (const c of cols.slice(1)) {
        const v = String(r[c] == null ? '' : r[c]).trim().toLowerCase();
        if (v && v !== '0' && v !== 'false' && v !== 'no') out[name][c.trim()] = 1;
      }
    }
    return out;
  }

  /* ---------------- applying parsed tables ---------------- */
  function blankValues(zones) {
    return { cost: 3, difficulty: 3, missing: 3, lack: 3, zones: Object.fromEntries(zones.map((z) => [z, 0])) };
  }

  /** Make any state-like object safe to use: fills gaps, drops dangling references. */
  function normalize(s) {
    const st = {
      version: 1,
      actors: Array.isArray(s.actors) ? s.actors.map(String) : [],
      zones: Array.isArray(s.zones) ? s.zones.map(String) : [],
      attacks: Array.isArray(s.attacks) ? s.attacks : [],
      defenses: Array.isArray(s.defenses) ? s.defenses : [],
      layers: Array.isArray(s.layers) ? s.layers : [],
      mapping: s.mapping && typeof s.mapping === 'object' ? s.mapping : {},
      view: s.view && typeof s.view === 'object' ? s.view : {},
    };
    st.attacks = st.attacks.map((a) => ({
      id: a.id || uid('a_'), name: String(a.name || 'Attack'), tactic: String(a.tactic || ''),
      impact: score15(a.impact), probability: score15(a.probability), means: score15(a.means),
      actors: Object.fromEntries(st.actors.map((x) => [x, clamp(a.actors && a.actors[x], 0, 1, 0)])),
    }));
    st.defenses = st.defenses.map((d) => ({ id: d.id || uid('d_'), name: String(d.name || 'Defense'), category: String(d.category || '') }));
    if (!st.layers.length) st.layers = [{ id: uid('l_'), name: 'Baseline', values: {} }];
    st.layers = st.layers.map((l) => {
      const values = {};
      for (const d of st.defenses) {
        const v = (l.values && l.values[d.id]) || blankValues(st.zones);
        values[d.id] = {
          cost: score15(v.cost), difficulty: score15(v.difficulty), missing: score15(v.missing), lack: score15(v.lack),
          zones: Object.fromEntries(st.zones.map((z) => [z, Math.round(clamp(v.zones && v.zones[z], 0, 5, 0))])),
        };
      }
      return { id: l.id || uid('l_'), name: String(l.name || 'Layer'), values };
    });
    const aIds = new Set(st.attacks.map((a) => a.id));
    const dIds = new Set(st.defenses.map((d) => d.id));
    const mapping = {};
    for (const [aid, row] of Object.entries(st.mapping)) {
      if (!aIds.has(aid) || !row) continue;
      mapping[aid] = {};
      for (const [did, v] of Object.entries(row)) if (dIds.has(did) && num(v) > 0) mapping[aid][did] = 1;
    }
    st.mapping = mapping;
    const lIds = st.layers.map((l) => l.id);
    const v = st.view;
    st.view = {
      actors: (v.actors || []).filter((x) => st.actors.includes(x)),
      zone: st.zones.includes(v.zone) ? v.zone : '',
      layers: (v.layers || []).filter((x) => lIds.includes(x)),
      cert: !!v.cert,
      compare: (v.compare || lIds).filter((x) => lIds.includes(x)),
    };
    if (!st.view.layers.length) st.view.layers = [lIds[0]];
    return st;
  }

  /**
   * Apply parsed tables onto a state.
   * tables: { attacks?: rows, defenses?: rows, mapping?: rows }
   * mode: 'replace' (tables replace the matching parts) or 'layer' (defense tables are added as new layers)
   */
  function applyTables(state, tables, mode, fileLabel) {
    const st = JSON.parse(JSON.stringify(state));
    if (tables.attacks && mode !== 'layer') {
      const p = parseAttacks(tables.attacks);
      const oldByName = Object.fromEntries(st.attacks.map((a) => [a.name, a.id]));
      st.actors = p.actors;
      st.attacks = p.attacks.map((a) => ({ ...a, id: oldByName[a.name] || a.id }));
    }
    if (tables.defenses) {
      const p = parseDefenses(tables.defenses, fileLabel);
      if (mode === 'layer') {
        for (const z of p.zones) if (!st.zones.includes(z)) {
          st.zones.push(z);
          for (const l of st.layers) for (const v of Object.values(l.values)) v.zones[z] = 0;
        }
        for (const d of p.defenses) if (!st.defenses.find((x) => x.name === d.name)) {
          const nd = { id: uid('d_'), name: d.name, category: d.category };
          st.defenses.push(nd);
          for (const l of st.layers) l.values[nd.id] = blankValues(st.zones);
        }
        for (const pl of p.layers) {
          const values = {};
          for (const d of st.defenses) {
            const v = pl.values[d.name];
            values[d.id] = v
              ? { ...v, zones: Object.fromEntries(st.zones.map((z) => [z, num(v.zones[z])])) }
              : blankValues(st.zones);
          }
          const layer = { id: uid('l_'), name: uniqueName(pl.name, st.layers.map((l) => l.name)), values };
          st.layers.push(layer);
          st.view.compare = (st.view.compare || []).concat(layer.id);
        }
      } else {
        const oldByName = Object.fromEntries(st.defenses.map((d) => [d.name, d.id]));
        st.zones = p.zones;
        st.defenses = p.defenses.map((d) => ({ id: oldByName[d.name] || uid('d_'), name: d.name, category: d.category }));
        const idByName = Object.fromEntries(st.defenses.map((d) => [d.name, d.id]));
        st.layers = p.layers.map((pl) => {
          const values = {};
          for (const [name, v] of Object.entries(pl.values)) values[idByName[name]] = v;
          return { id: uid('l_'), name: pl.name, values };
        });
        st.view.layers = [st.layers[0].id];
        st.view.compare = st.layers.map((l) => l.id);
      }
    }
    if (tables.mapping) {
      const m = parseMapping(tables.mapping);
      const aByName = Object.fromEntries(st.attacks.map((a) => [a.name, a.id]));
      const dByName = Object.fromEntries(st.defenses.map((d) => [d.name, d.id]));
      if (mode !== 'layer') st.mapping = {};
      for (const [an, row] of Object.entries(m)) {
        const aid = aByName[an];
        if (!aid) continue;
        st.mapping[aid] = st.mapping[aid] || {};
        for (const dn of Object.keys(row)) if (dByName[dn]) st.mapping[aid][dByName[dn]] = 1;
      }
    }
    return normalize(st);
  }

  return {
    uid, uniqueName, zoneLevel, csvParse, csvStringify,
    attacksTable, defensesTable, mappingTable, headers, classify,
    parseAttacks, parseDefenses, parseMapping, blankValues, normalize, applyTables,
  };
});
