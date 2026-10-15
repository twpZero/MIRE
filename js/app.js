/* MIRE web UI — vanilla JS, no build step. */
(function () {
  'use strict';

  const M = window.MIRE;
  const IO = window.MIRE_IO;
  const DEF = window.MIRE_DEFAULTS;
  const KEY = 'mire.state.v1';
  const TABS = ['dashboard', 'attacks', 'defenses', 'mapping', 'compare', 'data', 'method'];

  const LEVEL_NAME = Object.fromEntries(M.LEVELS.map((l) => [l.v, l.name]));
  const ZONE_NAME = { 1: 'fully covered', 2: 'minor gaps', 3: 'partial', 4: 'mostly missing', 5: 'not deployed' };
  const zoneTitle = (z) => `Missing coverage ${z}: ${ZONE_NAME[z]}${z === M.NOT_DEPLOYED ? ' (maximum risk)' : ''}`;
  const $view = document.getElementById('view');
  let state = load();
  const ui = { tab: 'dashboard', editLayer: state.layers[0].id, importMode: 'replace' };

  /* ---------------- persistence ---------------- */
  function load() {
    try {
      const raw = localStorage.getItem(KEY);
      if (raw) return IO.normalize(JSON.parse(raw));
    } catch (e) { /* storage unavailable or corrupt: fall back to defaults */ }
    return IO.normalize(DEF.build());
  }
  let saveTimer;
  function save() {
    clearTimeout(saveTimer);
    saveTimer = setTimeout(() => {
      try { localStorage.setItem(KEY, JSON.stringify(state)); } catch (e) { /* ignore */ }
    }, 200);
  }
  function setState(next, msg) {
    state = IO.normalize(next);
    if (!state.layers.find((l) => l.id === ui.editLayer)) ui.editLayer = state.layers[0].id;
    save();
    render();
    if (msg) toast(msg);
  }
  function commit(rerender = true) {
    save();
    if (rerender) render();
  }

  /* ---------------- helpers ---------------- */
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
  const attackById = (id) => state.attacks.find((a) => a.id === id);
  const defenseById = (id) => state.defenses.find((d) => d.id === id);
  const layerById = (id) => state.layers.find((l) => l.id === id);
  function fmt(n) {
    if (!Number.isFinite(n)) return '–';
    if (Math.abs(n) >= 1000) return Math.round(n).toLocaleString('en-US');
    if (Math.abs(n) >= 100) return String(Math.round(n));
    if (Math.abs(n) >= 10) return n.toFixed(1).replace(/\.0$/, '');
    return n.toFixed(2).replace(/\.?0+$/, '') || '0';
  }
  const pct = (n) => (n >= 10 ? n.toFixed(0) : n >= 1 ? n.toFixed(1) : n.toFixed(2)) + '%';
  // log colour scale between the smallest and largest positive values shown
  function heat(value, max, min) {
    if (!(value > 0) || !(max > 0)) return { bg: 'var(--heat-0)', fg: 'var(--muted)', t: 0 };
    const lo = Math.log(Math.max(1, min || 1));
    const hi = Math.log(Math.max(max, 1));
    const t = hi > lo ? Math.min(1, Math.max(0, (Math.log(Math.max(value, 1)) - lo) / (hi - lo))) : 1;
    return { bg: `color-mix(in srgb, var(--heat-1) ${Math.round(t * 100)}%, var(--heat-0))`, fg: t > 0.55 ? '#fff' : 'var(--text)', t };
  }
  let toastTimer;
  function toast(msg) {
    const el = document.getElementById('toast');
    el.textContent = msg;
    el.classList.add('show');
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.remove('show'), 2600);
  }
  function download(name, content, type) {
    const blob = content instanceof Blob ? content : new Blob([content], { type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = name;
    document.body.appendChild(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
  }
  const stamp = () => new Date().toISOString().slice(0, 10);

  function viewOpts(extra) {
    const v = state.view;
    return {
      actors: v.actors,
      zones: v.zones,
      layerIds: v.layers,
      cert: v.cert,
      ...extra,
    };
  }

  /* ---------------- shared controls ---------------- */
  function controlsHTML({ layers }) {
    const v = state.view;
    const actorChips = state.actors.map((x) =>
      `<button class="chip" data-act="toggleActor" data-x="${esc(x)}" aria-pressed="${v.actors.includes(x)}">${esc(x)}</button>`).join('');
    const zoneChips = state.zones.map((z) =>
      `<button class="chip" data-act="toggleZone" data-z="${esc(z)}" aria-pressed="${v.zones.includes(z)}">${esc(z)}</button>`).join('');
    const layerOpts = state.layers.map((l) => `<option value="${l.id}" ${v.layers[0] === l.id ? 'selected' : ''}>${esc(l.name)}</option>`).join('');
    return `
      <div class="card controls">
        <div class="ctrl-group">
          <span class="ctrl-label">Threat actors <span class="muted" style="text-transform:none;letter-spacing:0">(max of selected · none = all attacks)</span></span>
          <div class="chips">${actorChips || '<span class="muted small">No actor columns yet</span>'}</div>
        </div>
        <div class="ctrl-group">
          <span class="ctrl-label">Zones <span class="muted" style="text-transform:none;letter-spacing:0">(several = weakest setting per line)</span></span>
          <div class="chips">${zoneChips || '<span class="muted small">No zone columns yet</span>'}</div>
        </div>
        ${layers ? `<div class="ctrl-group">
          <label for="layerSel">Defense layer</label>
          <select id="layerSel" data-view="layer">${layerOpts}</select>
        </div>` : ''}
        <div class="ctrl-group">
          <span class="ctrl-label">View</span>
          <label class="switch" title="CERT view ignores cost and operational difficulty: what you should do, regardless of whether you can.">
            <input type="checkbox" data-view="cert" ${v.cert ? 'checked' : ''}> CERT view
          </label>
        </div>
      </div>`;
  }

  // defense ranking: best blocking score first, unique reduction breaks ties
  const byBlocking = (a, b) => b.blocking - a.blocking || b.unique - a.unique;

  /* ---------------- Dashboard ---------------- */
  function renderDashboard() {
    const opts = viewOpts();
    const res = M.compute(state, opts);
    const rows = res.attacks.rows.filter((r) => r.w > 0).sort((a, b) => b.mire - a.mire);
    const maxMire = rows.length ? rows[0].mire : 0;
    const unmit = rows.filter((r) => !r.coveredZones);
    const defs = res.defenses.slice().sort(byBlocking);
    const maxUnique = Math.max(0, ...defs.map((d) => d.unique));
    const maxBlock = Math.max(0, ...defs.map((d) => d.blocking));
    const exposurePct = rows.length ? (100 * rows.reduce((s, r) => s + r.mire, 0)) / (M.A_MAX * res.attacks.dMax * rows.length) : 0;
    const layerNames = layerById(state.view.layers[0]).name;
    const layerValues = M.mergeLayers(state, state.view.layers);
    const all = M.computeAttacks(state, { ...opts, zones: state.zones, values: layerValues, perZone: true });
    const heatVals = all.rows.filter((r) => r.w > 0).flatMap((r) => state.zones.map((z) => r.perZone[z].mire)).filter((x) => x > 0);
    const allMax = Math.max(0, ...heatVals);
    const allMin = Math.min(allMax, ...heatVals);

    const deployedIn = (id) => state.view.zones.filter((z) => M.num(layerValues[id] && layerValues[id].zones[z], M.NOT_DEPLOYED) < M.NOT_DEPLOYED).length;
    const attackRows = rows.map((r, i) => {
      const d = r.by ? defenseById(r.by) : null;
      return `<tr>
        <td class="num muted">${i + 1}</td>
        <td>${esc(r.attack.name)}</td>
        <td class="muted">${esc(r.attack.tactic)}</td>
        <td class="num">${r.A}</td>
        <td>${d ? esc(d.name) : '<span class="pill bad">unmitigated</span>'}</td>
        <td class="num">${fmt(r.D)}</td>
        <td class="num"><strong>${fmt(r.mire)}</strong></td>
        <td class="num muted">${pct(r.norm)}</td>
        <td><div class="bar"><i style="width:${maxMire ? (100 * r.mire) / maxMire : 0}%"></i></div></td>
      </tr>`;
    }).join('');

    const defRows = defs.map((d, i) => `<tr>
        <td class="num muted">${i + 1}</td>
        <td>${esc(d.defense.name)}</td>
        <td class="muted">${esc(d.defense.category)}</td>
        <td class="center">${deployedIn(d.id) ? `${deployedIn(d.id)}/${state.view.zones.length}` : '<span class="pill">not deployed</span>'}</td>
        <td class="num">${fmt(d.feasibility)}</td>
        <td class="num">${d.covered}</td>
        <td class="num">${d.bestFor}</td>
        <td class="num"><strong>${fmt(d.blocking)}</strong></td>
        <td><div class="bar good"><i style="width:${maxBlock ? (100 * d.blocking) / maxBlock : 0}%"></i></div></td>
        <td class="num">${fmt(d.unique)}</td>
        <td><div class="bar good"><i style="width:${maxUnique ? (100 * d.unique) / maxUnique : 0}%"></i></div></td>
      </tr>`).join('');

    const heatRows = all.rows.filter((r) => r.w > 0).map((r) => `<tr>
        <td class="sticky-col">${esc(r.attack.name)}</td>
        ${state.zones.map((z) => {
          const c = r.perZone[z];
          const h = heat(c.mire, allMax, allMin);
          const by = c.by ? defenseById(c.by).name : 'no defense';
          return `<td class="heat" style="background:${h.bg};color:${h.fg}" title="${esc(z)} · ${esc(by)} · D=${fmt(c.D)}">${fmt(c.mire)}</td>`;
        }).join('')}
      </tr>`).join('');

    return `
      ${controlsHTML({ layers: true })}
      <div class="kpis">
        <div class="kpi"><div class="label">Residual exposure</div><div class="value">${pct(exposurePct)}</div>
          <div class="sub" title="Sum of MIRE over in-scope attacks">Σ MIRE ${fmt(res.attacks.rows.reduce((s, r) => s + r.mire, 0))}</div></div>
        <div class="kpi"><div class="label">Attack steps in scope</div><div class="value">${rows.length}<span class="muted" style="font-size:14px"> / ${state.attacks.length}</span></div>
          <div class="sub">${state.view.actors.length ? esc(state.view.actors.join(', ')) : 'all actors'}</div></div>
        <div class="kpi"><div class="label">Unmitigated steps</div><div class="value" style="color:${unmit.length ? 'var(--bad)' : 'var(--ok)'}">${unmit.length}</div>
          <div class="sub">${unmit.length ? esc(unmit.slice(0, 3).map((r) => r.attack.name).join(', ')) : 'every step has a control'}</div></div>
        <div class="kpi"><div class="label">Highest residual</div><div class="value" style="font-size:16px;line-height:1.5">${rows[0] ? esc(rows[0].attack.name) : '–'}</div>
          <div class="sub">${rows[0] ? 'MIRE ' + fmt(rows[0].mire) : ''}</div></div>
        <div class="kpi"><div class="label">Most valuable defense</div><div class="value" style="font-size:16px;line-height:1.5">${defs[0] && defs[0].blocking > 0 ? esc(defs[0].defense.name) : '–'}</div>
          <div class="sub">${esc(layerNames)}${state.view.cert ? ' · CERT view' : ''}</div></div>
      </div>

      <div class="card">
        <div class="row"><h3 style="margin:0">Attack ranking — highest residual exposure first</h3><span class="spacer"></span>
          <span class="muted small">MIRE = A × actor × D<sub>min</sub>${state.view.cert ? ' (D ignores cost &amp; difficulty)' : ''}</span></div>
        <div class="table-wrap tall" style="margin-top:10px"><table>
          <thead><tr><th class="num">#</th><th>Attack step</th><th>Tactic</th><th class="num" title="Impact × Probability × Means">A</th>
            <th title="Best mapped control in the selected zone(s)">Best control</th><th class="num" title="Residual score of the best mapped defense">D</th>
            <th class="num">MIRE</th><th class="num" title="Share of the theoretical maximum">% max</th><th></th></tr></thead>
          <tbody>${attackRows || '<tr><td colspan="10" class="muted">No attack in scope — select other actors or add attacks.</td></tr>'}</tbody>
        </table></div>
      </div>

      <div class="card">
        <div class="row"><h3 style="margin:0">Defense ranking — best blocking score first</h3><span class="spacer"></span>
          <span class="muted small">Unique reduction = MIRE added if the defense were removed · Blocking = risk it absorbs on its own</span></div>
        <div class="table-wrap tall" style="margin-top:10px"><table>
          <thead><tr><th class="num">#</th><th>Defense</th><th>Category</th><th class="center" title="Selected zones where the defense is deployed">Zones</th><th class="num" title="${state.view.cert ? 'Lack of efficiency (CERT view)' : 'Cost × Difficulty × Lack'}">Feasibility</th>
            <th class="num" title="In-scope attacks mapped to this defense">Covers</th><th class="num" title="Attacks where it is the best control">Best for</th>
            <th class="num">Blocking</th><th></th><th class="num">Unique reduction</th><th></th></tr></thead>
          <tbody>${defRows}</tbody>
        </table></div>
      </div>

      <div class="card">
        <div class="row"><h3 style="margin:0">Residual heatmap — attack × zone</h3><span class="spacer"></span>
          <span class="muted small">Log colour scale · hover a cell for the best control</span></div>
        <div class="table-wrap tall" style="margin-top:10px"><table>
          <thead><tr><th class="sticky-col">Attack step</th>${state.zones.map((z) => `<th class="center" ${state.view.zones.includes(z) ? 'style="color:var(--accent)" title="Selected zone"' : ''}>${esc(z)}</th>`).join('')}</tr></thead>
          <tbody>${heatRows}</tbody>
        </table></div>
      </div>`;
  }

  /* ---------------- grid cells (attacks, defenses, mapping) ---------------- */
  const editValues = (el) => layerById(ui.editLayer).values[el.dataset.id];
  const CELLS = {
    attack: {
      min: 1, max: 5, show: (v) => v, label: (v) => String(v),
      get: (el) => attackById(el.dataset.id)[el.dataset.f],
      set: (el, v) => {
        const a = attackById(el.dataset.id);
        a[el.dataset.f] = v;
        paintCalc($view.querySelector(`[data-ascore="${a.id}"]`), M.attackScore(a));
      },
    },
    actor: {
      min: 0, max: 1, show: (v) => (v ? '●' : ''), label: (v) => (v ? 'uses this technique' : 'does not use it'),
      get: (el) => (M.num(attackById(el.dataset.id).actors[el.dataset.x]) > 0 ? 1 : 0),
      set: (el, v) => { attackById(el.dataset.id).actors[el.dataset.x] = v; },
    },
    feas: {
      min: 1, max: 5, show: (v) => v, label: (v) => String(v),
      get: (el) => editValues(el)[el.dataset.f],
      set: (el, v) => {
        const x = editValues(el);
        x[el.dataset.f] = v;
        paintCalc($view.querySelector(`[data-dscore="${el.dataset.id}"]`), M.feasibility(x, false));
      },
    },
    zone: {
      min: 1, max: 5, show: (v) => v, label: (v) => zoneTitle(v),
      get: (el) => editValues(el).zones[el.dataset.z],
      set: (el, v) => { editValues(el).zones[el.dataset.z] = v; },
    },
    map: {
      min: 0, max: 5, show: (v) => v || '', label: (v) => (v ? `${v} ${LEVEL_NAME[v]}` : 'no effect'),
      get: (el) => M.num((state.mapping[el.dataset.a] || {})[el.dataset.d]),
      set: (el, v) => {
        const { a, d } = el.dataset;
        const row = (state.mapping[a] = state.mapping[a] || {});
        const delta = (v > 0 ? 1 : 0) - (M.num(row[d]) > 0 ? 1 : 0);
        if (v > 0) row[d] = v; else delete row[d];
        if (!delta) return;
        for (const c of [$view.querySelector(`[data-rcount="${a}"]`), $view.querySelector(`[data-ccount="${d}"]`)]) {
          if (!c) continue;
          const n = Number(c.textContent) + delta;
          c.textContent = n;
          c.classList.toggle('zero', n === 0);
        }
      },
    },
  };
  function cellHTML(kind, v, attrs, label) {
    const k = CELLS[kind];
    return `<td class="cell k-${kind}" tabindex="0" data-act="cell" data-kind="${kind}" data-v="${v}" ${attrs} data-t="${esc(label)}" title="${esc(label)}: ${esc(k.label(v))}">${k.show(v)}</td>`;
  }
  function setCell(el, v) {
    const k = CELLS[el.dataset.kind];
    v = Math.min(k.max, Math.max(k.min, v));
    k.set(el, v);
    el.dataset.v = v;
    el.textContent = k.show(v);
    el.title = `${el.dataset.t}: ${k.label(v)}`;
    commit(false);
  }
  // products of three 1–5 scores (1 … 125); square-root scale keeps mid values readable
  const calcStyle = (value) => {
    const t = Math.sqrt(Math.max(0, Math.min(125, value)) / 125);
    return `background:color-mix(in srgb, var(--heat-1) ${Math.round(t * 85)}%, var(--heat-0));color:${t > 0.7 ? '#fff' : 'var(--text)'}`;
  };
  function paintCalc(el, value) {
    if (!el) return;
    el.textContent = value;
    el.setAttribute('style', calcStyle(value));
  }
  const vertHead = (label, title, extra = '') => `<th class="vert ${extra}" title="${esc(title || label)}"><div>${esc(label)}</div></th>`;
  const editHead = (label, act, delAct, key, attr) => `<th class="vert" title="${esc(label)} — click to rename">
      <button class="x" data-act="${delAct}" ${attr}="${esc(key)}" title="Remove" aria-label="Remove ${esc(label)}">×</button>
      <div><span data-act="${act}" ${attr}="${esc(key)}">${esc(label)}</span></div></th>`;
  const scoreLegend = (low, high) => `<span>Score:</span>${[1, 2, 3, 4, 5].map((n) => `<span class="lvl" data-v="${n}"><b>${n}</b></span>`).join('')}<span>${low} → ${high}</span>`;
  const cellHint = 'Click a coloured cell to cycle (Shift+click backwards), or focus it and type a digit.';

  /* ---------------- Attacks ---------------- */
  function renderAttacks() {
    const tacticList = `<datalist id="tactics">${DEF.TACTICS.map((t) => `<option value="${esc(t)}">`).join('')}</datalist>`;
    const actorHeads = state.actors.map((x, i) => editHead(x, 'renameActor', 'delActor', x, 'data-x').replace('class="vert"', `class="vert${i ? '' : ' sep'}"`)).join('');
    const rows = state.attacks.map((a) => {
      const score = (f, label) => cellHTML('attack', a[f], `data-id="${a.id}" data-f="${f}"`, `${a.name} — ${label}`);
      return `<tr data-row="${a.id}" data-search="${esc((a.name + ' ' + a.tactic).toLowerCase())}">
        <td class="sticky-col">
          <input class="ghost" type="text" value="${esc(a.name)}" data-edit="attack" data-id="${a.id}" data-f="name" aria-label="Attack name">
          <input class="ghost sub" type="text" list="tactics" value="${esc(a.tactic)}" placeholder="Tactic…" data-edit="attack" data-id="${a.id}" data-f="tactic" aria-label="Tactic">
        </td>
        ${score('impact', 'Impact')}${score('probability', 'Probability')}${score('means', 'Means')}
        <td class="calc" data-ascore="${a.id}" style="${calcStyle(M.attackScore(a))}" title="A = Impact × Probability × Means">${M.attackScore(a)}</td>
        ${state.actors.map((x, i) => cellHTML('actor', M.num(a.actors[x]) > 0 ? 1 : 0, `data-id="${a.id}" data-x="${esc(x)}"`, `${x} — ${a.name}`).replace('class="cell', i ? 'class="cell' : 'class="sep cell')).join('')}
        <td class="del"><button class="x" data-act="delAttack" data-id="${a.id}" title="Delete attack" aria-label="Delete ${esc(a.name)}">×</button></td>
      </tr>`;
    }).join('');
    return `
      <div class="card">
        <div class="row">
          <div><h2 style="margin:0">Attacks</h2><p class="muted small" style="margin:2px 0 0">Each line is an attack step or means, scored 1–5. Actor columns mark the threat actors that use the technique. ${cellHint}</p></div>
          <span class="spacer"></span>
          <input type="search" placeholder="Filter attacks…" data-filter="attacks" aria-label="Filter attacks">
          <button class="btn" data-act="addActor">+ Actor</button>
          <button class="btn primary" data-act="addAttack">+ Attack</button>
        </div>
        <div class="legend" style="margin-top:10px">${scoreLegend('low', 'high')}<span>· <b>A</b> = Impact × Probability × Means</span><span class="lvl-actor"><b>●</b> actor uses the technique</span></div>
      </div>
      ${tacticList}
      <div class="table-wrap tall"><table class="matrix">
        <thead><tr><th class="sticky-col" style="vertical-align:bottom">Attack step · tactic</th>
          ${vertHead('Impact', 'Impact — 1 low … 5 critical')}${vertHead('Probability', 'Probability — 1 rare … 5 almost certain')}${vertHead('Means', 'Means — 1 hard to obtain … 5 commodity')}
          ${vertHead('A', 'Impact × Probability × Means')}${actorHeads}<th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>`;
  }

  /* ---------------- Defenses ---------------- */
  function renderDefenses() {
    const layer = layerById(ui.editLayer) || state.layers[0];
    ui.editLayer = layer.id;
    const layerChips = state.layers.map((l) => `<button class="chip" data-act="editLayer" data-id="${l.id}" aria-pressed="${l.id === layer.id}">${esc(l.name)}</button>`).join('');
    const zoneHeads = state.zones.map((z, i) => editHead(z, 'renameZone', 'delZone', z, 'data-z').replace('class="vert"', `class="vert${i ? '' : ' sep'}"`)).join('');
    const rows = state.defenses.map((d) => {
      const v = layer.values[d.id];
      const feas = (f, label) => cellHTML('feas', v[f], `data-id="${d.id}" data-f="${f}"`, `${d.name} — ${label}`);
      return `<tr data-row="${d.id}" data-search="${esc((d.name + ' ' + d.category).toLowerCase())}">
        <td class="sticky-col">
          <input class="ghost" type="text" value="${esc(d.name)}" data-edit="defense" data-id="${d.id}" data-f="name" aria-label="Defense name">
          <input class="ghost sub" type="text" value="${esc(d.category)}" placeholder="Category…" data-edit="defense" data-id="${d.id}" data-f="category" aria-label="Category">
        </td>
        ${feas('cost', 'Cost')}${feas('difficulty', 'Operational difficulty')}${feas('lack', 'Lack of efficiency')}
        <td class="calc" data-dscore="${d.id}" style="${calcStyle(M.feasibility(v, false))}" title="Cost × Difficulty × Lack">${M.feasibility(v, false)}</td>
        ${state.zones.map((z, i) => cellHTML('zone', v.zones[z], `data-id="${d.id}" data-z="${esc(z)}"`, `${d.name} in ${z}`).replace('class="cell', i ? 'class="cell' : 'class="sep cell')).join('')}
        <td class="del"><button class="x" data-act="delDefense" data-id="${d.id}" title="Delete defense (all layers)" aria-label="Delete ${esc(d.name)}">×</button></td>
      </tr>`;
    }).join('');
    return `
      <div class="card">
        <div class="row">
          <div><h2 style="margin:0">Defenses</h2><p class="muted small" style="margin:2px 0 0">Feasibility scored 1–5 (higher = worse). Zone columns hold the missing coverage of the control in each zone. ${cellHint}</p></div>
          <span class="spacer"></span>
          <input type="search" placeholder="Filter defenses…" data-filter="defenses" aria-label="Filter defenses">
          <button class="btn" data-act="addZone">+ Zone</button>
          <button class="btn primary" data-act="addDefense">+ Defense</button>
        </div>
        <div class="row" style="margin-top:12px">
          <span class="ctrl-label">Editing layer</span>
          <div class="layer-tabs">${layerChips}</div>
          <span class="spacer"></span>
          <button class="btn" data-act="dupLayer" title="Copy this layer to model a project">Duplicate</button>
          <button class="btn" data-act="newLayer">New empty</button>
          <button class="btn" data-act="renameLayer">Rename</button>
          <button class="btn danger" data-act="delLayer" ${state.layers.length < 2 ? 'disabled' : ''}>Delete</button>
        </div>
        <div class="legend" style="margin-top:10px">${scoreLegend('easy', 'hard')}<span>· <b>C·D·L</b> = Cost × Difficulty × Lack</span></div>
        <div class="legend" style="margin-top:6px">
          <span>Zone = missing coverage:</span>${[1, 2, 3, 4, 5].map((n) => `<span class="lvlz" data-v="${n}"><b>${n}</b> ${ZONE_NAME[n]}</span>`).join('')}
          <span>· Names and categories are shared by all layers; scores are per layer.</span>
        </div>
      </div>
      <div class="table-wrap tall"><table class="matrix">
        <thead><tr><th class="sticky-col" style="vertical-align:bottom">Defense · category</th>
          ${vertHead('Cost')}${vertHead('Op. difficulty', 'Operational difficulty')}${vertHead('Lack of efficiency')}
          ${vertHead('C·D·L', 'Cost × Difficulty × Lack')}${zoneHeads}<th></th></tr></thead>
        <tbody>${rows}</tbody>
      </table></div>`;
  }

  /* ---------------- Mapping ---------------- */
  function renderMapping() {
    const colCount = Object.fromEntries(state.defenses.map((d) => [d.id, 0]));
    const body = state.attacks.map((a) => {
      const row = state.mapping[a.id] || {};
      let n = 0;
      const cells = state.defenses.map((d) => {
        const lv = M.num(row[d.id]);
        if (lv > 0) { n++; colCount[d.id]++; }
        return cellHTML('map', lv, `data-a="${a.id}" data-d="${d.id}"`, `${a.name} ↔ ${d.name}`);
      }).join('');
      return `<tr data-row="${a.id}" data-search="${esc((a.name + ' ' + a.tactic).toLowerCase())}">
        <td class="sticky-col">${esc(a.name)}<div class="muted small">${esc(a.tactic)}</div></td>${cells}
        <td class="count ${n ? '' : 'zero'}" data-rcount="${a.id}">${n}</td></tr>`;
    }).join('');
    return `
      <div class="card">
        <div class="row">
          <div><h2 style="margin:0">Mapping</h2><p class="muted small" style="margin:2px 0 0">How each defense acts on each attack step. Click to cycle (Shift+click backwards), or focus a cell and type 0–5. Rows with 0 are blind spots.</p></div>
          <span class="spacer"></span>
          <input type="search" placeholder="Filter attacks…" data-filter="mapping" aria-label="Filter attacks">
        </div>
        <div class="legend" style="margin-top:10px"><span>Action:</span>${M.LEVELS.map((l) => `<span class="lvl" data-v="${l.v}"><b>${l.v}</b> ${l.name}</span>`).join('')}<span><b>empty</b> no effect</span></div>
      </div>
      <div class="table-wrap tall"><table class="matrix">
        <thead><tr><th class="sticky-col" style="vertical-align:bottom">Attack \\ Defense</th>
          ${state.defenses.map((d) => `<th class="vert" title="${esc(d.name)}"><div>${esc(d.name)}</div></th>`).join('')}<th class="center" style="vertical-align:bottom">#</th></tr></thead>
        <tbody>${body}
          <tr><td class="sticky-col muted small">Attacks covered</td>${state.defenses.map((d) => `<td class="count ${colCount[d.id] ? '' : 'zero'}" data-ccount="${d.id}">${colCount[d.id]}</td>`).join('')}<td></td></tr>
        </tbody>
      </table></div>`;
  }

  /* ---------------- Compare ---------------- */
  function renderCompare() {
    const v = state.view;
    const chosen = state.layers.filter((l) => v.compare.includes(l.id));
    const chips = state.layers.map((l) => `<button class="chip" data-act="toggleCompare" data-id="${l.id}" aria-pressed="${v.compare.includes(l.id)}">${esc(l.name)}</button>`).join('');
    const results = chosen.map((l) => ({ layer: l, res: M.computeAttacks(state, viewOpts({ layerIds: [l.id] })) }));
    let body = '<p class="muted">Select at least one layer to compare.</p>';
    if (results.length) {
      const inScope = (r) => r.w > 0;
      const totals = results.map(({ res }) => res.rows.filter(inScope).reduce((s, r) => s + r.mire, 0));
      const maxTotal = Math.max(...totals, 1);
      const base = totals[0];
      const summary = results.map(({ layer, res }, i) => {
        const unmit = res.rows.filter((r) => inScope(r) && !r.coveredZones).length;
        const delta = base ? (100 * (totals[i] - base)) / base : 0;
        return `<tr><td><strong>${esc(layer.name)}</strong></td>
          <td class="num">${fmt(totals[i])}</td>
          <td style="width:40%"><div class="bar"><i style="width:${(100 * totals[i]) / maxTotal}%"></i></div></td>
          <td class="num ${delta < 0 ? 'delta-down' : delta > 0 ? 'delta-up' : 'muted'}">${i === 0 ? 'reference' : (delta > 0 ? '+' : '') + delta.toFixed(1) + '%'}</td>
          <td class="num">${unmit}</td></tr>`;
      }).join('');
      const ref = results[0].res.rows;
      const order = ref.map((r, i) => i).filter((i) => inScope(ref[i])).sort((a, b) => ref[b].mire - ref[a].mire);
      const cmpVals = results.flatMap(({ res }) => order.map((i) => res.rows[i].mire)).filter((x) => x > 0);
      const allMax = Math.max(1, ...cmpVals);
      const allMin = Math.min(allMax, ...cmpVals);
      const detail = order.map((i) => `<tr><td class="sticky-col">${esc(ref[i].attack.name)}</td>${results.map(({ res }, k) => {
        const r = res.rows[i];
        const h = heat(r.mire, allMax, allMin);
        const d = k ? r.mire - ref[i].mire : 0;
        return `<td class="heat" style="background:${h.bg};color:${h.fg}" title="${esc(r.by ? defenseById(r.by).name : 'unmitigated')}">${fmt(r.mire)}${d ? `<div class="small">${d > 0 ? '▲' : '▼'} ${fmt(Math.abs(d))}</div>` : ''}</td>`;
      }).join('')}</tr>`).join('');
      body = `
        <div class="table-wrap"><table>
          <thead><tr><th>Layer / project</th><th class="num">Σ MIRE</th><th></th><th class="num">vs reference</th><th class="num">Unmitigated</th></tr></thead>
          <tbody>${summary}</tbody></table></div>
        <h3 style="margin-top:18px">Per attack step</h3>
        <div class="table-wrap tall"><table>
          <thead><tr><th class="sticky-col">Attack step</th>${results.map(({ layer }) => `<th class="center">${esc(layer.name)}</th>`).join('')}</tr></thead>
          <tbody>${detail}</tbody></table></div>`;
    }
    return `
      ${controlsHTML({ layers: false })}
      <div class="card">
        <div class="row"><div><h3 style="margin:0">Compare residual risk between layers / projects</h3>
          <p class="muted small" style="margin:2px 0 0">The first selected layer is the reference. Duplicate the baseline in <em>Defenses</em> to model a budget option.</p></div></div>
        <div class="chips" style="margin:12px 0 16px">${chips}</div>
        ${body}
      </div>`;
  }

  /* ---------------- Import / Export ---------------- */
  function renderData() {
    const xlsxOk = typeof window.XLSX !== 'undefined';
    return `
      <div class="grid2">
        <div class="card">
          <h3>Export</h3>
          <p class="muted small">JSON keeps everything (all layers, mapping, view settings). XLSX holds one sheet per table plus the current results.</p>
          <div class="row">
            <button class="btn primary" data-act="exportJSON">JSON</button>
            <button class="btn" data-act="exportXLSX" ${xlsxOk ? '' : 'disabled title="Spreadsheet library failed to load"'}>XLSX workbook</button>
          </div>
          <p class="ctrl-label" style="margin-top:16px">CSV — one table per file</p>
          <div class="row">
            <button class="btn" data-act="exportCSV" data-t="attacks">Attacks</button>
            <button class="btn" data-act="exportCSV" data-t="defenses">Defenses (all layers)</button>
            <button class="btn" data-act="exportCSV" data-t="mapping">Mapping</button>
            <button class="btn" data-act="exportCSV" data-t="results">Results</button>
          </div>
        </div>
        <div class="card">
          <h3>Import</h3>
          <div class="row" style="margin-bottom:10px">
            <label class="switch"><input type="radio" name="imode" value="replace" data-imode ${ui.importMode === 'replace' ? 'checked' : ''} style="appearance:auto;width:auto;height:auto;background:none"> Replace matching tables</label>
            <label class="switch"><input type="radio" name="imode" value="layer" data-imode ${ui.importMode === 'layer' ? 'checked' : ''} style="appearance:auto;width:auto;height:auto;background:none"> Add defenses as new layer(s)</label>
          </div>
          <div class="drop" id="drop">
            Drop .json, .xlsx or .csv files here, or
            <label class="btn" style="margin-left:6px">choose files<input type="file" id="fileIn" multiple accept=".json,.xlsx,.xls,.csv,.txt" hidden></label>
          </div>
          <p class="muted small" style="margin-top:10px">CSV/XLSX tables are recognised by their headers: <code>Impact</code> → attacks, <code>Cost</code> → defenses (optional <code>Layer</code> column), first column <code>Attack</code> with defense names → mapping. Zone cells are missing coverage 1–5 (1 = fully covered, 5 or empty = not deployed). Mapping cells accept 0–5 or Deny/Defer/Degrade/Disrupt/Detect.</p>
        </div>
      </div>
      <div class="card" style="margin-top:16px">
        <h3>Dataset</h3>
        <div class="row">
          <button class="btn" data-act="loadDefaults">Restore default dataset</button>
          <button class="btn danger" data-act="blank">Start from a blank model</button>
          <span class="muted small">${state.attacks.length} attacks · ${state.actors.length} actors · ${state.defenses.length} defenses · ${state.zones.length} zones · ${state.layers.length} layers</span>
        </div>
      </div>`;
  }

  /* ---------------- Method ---------------- */
  function renderMethod() {
    return `<div class="card method" style="max-width:900px">
      <h2>How MIRE scores residual exposure</h2>
      <p>MIRE maps what attackers do against what the company has deployed, to show where the residual risk concentrates and how a budget decision (project X or Y) moves it.</p>
      <h3>1. Attacks</h3>
      <p>Each line is an attack step or means. <b>Impact</b>, <b>Probability</b> and <b>Means</b> (how available the technique is to an attacker) are scored 1–5. Actor columns are 0–1: 1 means the actor uses the technique.</p>
      <div class="formula">A = Impact × Probability × Means            (1 … 125)
w = max(actor flag over selected actors)      (all attacks when no actor is selected)</div>
      <h3>2. Defenses</h3>
      <p>Each line is a security tool, process or OS feature. Feasibility is scored 1–5, higher meaning worse: <b>Cost</b>, <b>Operational difficulty</b>, <b>Lack of efficiency</b>. Each zone column holds the <b>missing coverage</b> of the control in that zone: 1 fully covered … 4 mostly missing, <b>5 not deployed</b>. A control that is not deployed gives no protection there: the zone keeps the maximum risk unless another control covers it.</p>
      <h3>3. Mapping</h3>
      <p>Each mapping cell holds the action of a defense on an attack step (5D), from the best outcome to the weakest:</p>
      <div class="legend" style="margin-bottom:10px">${M.LEVELS.map((l) => `<span><b>${l.v}</b> ${l.name}</span>`).join('')}<span><b>0 / empty</b> no effect on this attack</span></div>
      <div class="formula">D(attack, defense, zone) = Cost × Difficulty × Lack × Missing(zone) × Action    (1 … 2500)
CERT view:                 Lack × Missing(zone) × Action                        (1 … 100)
Missing = 5 (not deployed): the defense is ignored in that zone</div>
      <p>The CERT view drops cost and difficulty: it maps what you should do regardless of whether you can afford it.</p>
      <h3>4. MIRE</h3>
      <p>Adding defenses keeps the best one (min); an attack with no mapped defense deployed in the zone keeps the maximum D = 3125 (125 in CERT view): unmitigated.</p>
      <div class="formula">D(attack, zone) = min D over mapped defenses deployed in the zone   (D_max if none)
MIRE(attack)    = A × w × D(attack, zone)
Several zones   = merged first: each defense keeps its weakest setting
                  (highest missing coverage) across the selected zones</div>
      <p>Selecting several zones on the dashboard is a conservative view of a heterogeneous estate: a defense only counts where it is deployed in <b>every</b> selected zone, at its weakest coverage among them.</p>
      <h3>5. Rankings</h3>
      <ul>
        <li><b>Attack ranking</b> — attacks sorted by MIRE: the weakest points to address or formally accept.</li>
        <li><b>Blocking score</b> — Σ A × w × (D_max − D) / D_max over the attacks a defense covers, averaged over the zones: risk it absorbs on its own. Defenses are ranked by this score.</li>
        <li><b>Unique reduction</b> — how much Σ MIRE grows if the defense is removed: the value it brings that no other control duplicates.</li>
      </ul>
      <h3>6. Layers</h3>
      <p>A layer is a full set of defense scores and missing coverage (the mapping is shared). Use layers for sites, subsidiaries or budget options. The dashboard evaluates one layer at a time; the <em>Compare</em> tab puts layers side by side to compare residual risk between projects.</p>
      <h3>Scales at a glance</h3>
      <p class="muted">MIRE ranges from 0 to 125 × 3125 = 390,625 (125 × 125 = 15,625 in CERT view). The “% max” column divides by that maximum; since the formula is multiplicative, colour scales are logarithmic.</p>
    </div>`;
  }

  /* ---------------- render ---------------- */
  const RENDER = {
    dashboard: renderDashboard, attacks: renderAttacks, defenses: renderDefenses, mapping: renderMapping,
    compare: renderCompare, data: renderData, method: renderMethod,
  };
  const filters = {};
  function render() {
    for (const b of document.querySelectorAll('#tabs button')) b.setAttribute('aria-selected', String(b.dataset.tab === ui.tab));
    const scrollX = $view.querySelector('.table-wrap.tall');
    const keep = scrollX ? { top: scrollX.scrollTop, left: scrollX.scrollLeft } : null;
    $view.innerHTML = RENDER[ui.tab]();
    const f = $view.querySelector('[data-filter]');
    if (f && filters[f.dataset.filter]) { f.value = filters[f.dataset.filter]; applyFilter(f); }
    if (ui.tab === 'data') bindDrop();
    if (keep && ui.keepScroll) {
      const w = $view.querySelector('.table-wrap.tall');
      if (w) { w.scrollTop = keep.top; w.scrollLeft = keep.left; }
    }
    ui.keepScroll = false;
  }
  function go(tab) {
    ui.tab = TABS.includes(tab) ? tab : 'dashboard';
    if (location.hash.slice(1) !== ui.tab) history.replaceState(null, '', '#' + ui.tab);
    render();
    window.scrollTo(0, 0);
  }
  function applyFilter(input) {
    const q = input.value.trim().toLowerCase();
    filters[input.dataset.filter] = q;
    for (const tr of $view.querySelectorAll('tr[data-search]')) tr.hidden = q && !tr.dataset.search.includes(q);
  }

  /* ---------------- actions ---------------- */
  function promptName(label, current, taken) {
    const v = window.prompt(label, current || '');
    if (v == null) return null;
    const name = v.trim();
    if (!name) return null;
    if (name !== current && taken.includes(name)) { toast(`"${name}" already exists`); return null; }
    return name;
  }
  function toggle(list, x) {
    const i = list.indexOf(x);
    if (i >= 0) list.splice(i, 1); else list.push(x);
  }
  function resultsRows() {
    const res = M.computeAttacks(state, viewOpts());
    return res.rows.filter((r) => r.w > 0).sort((a, b) => b.mire - a.mire).map((r, i) => ({
      Rank: i + 1, Attack: r.attack.name, Tactic: r.attack.tactic, A: r.A, 'Actor weight': r.w, Zones: state.view.zones.join(' + '),
      'Best control': r.by ? defenseById(r.by).name : 'unmitigated', D: r.D, MIRE: r.mire, '% max': +r.norm.toFixed(4),
    }));
  }
  function defenseResultRows() {
    return M.computeDefenses(state, viewOpts()).sort(byBlocking).map((d, i) => ({
      Rank: i + 1, Defense: d.defense.name, Category: d.defense.category, 'Deployed zones': d.deployed.join(' | '), Feasibility: d.feasibility,
      Covers: d.covered, 'Best for': d.bestFor, Blocking: +d.blocking.toFixed(3), 'Unique reduction': d.unique,
    }));
  }

  const actions = {
    toggleActor: (el) => { toggle(state.view.actors, el.dataset.x); commit(); },
    toggleZone: (el) => {
      toggle(state.view.zones, el.dataset.z);
      if (!state.view.zones.length) state.view.zones.push(el.dataset.z);
      state.view.zones.sort((a, b) => state.zones.indexOf(a) - state.zones.indexOf(b));
      commit();
    },
    toggleCompare: (el) => { toggle(state.view.compare, el.dataset.id); state.view.compare.sort((a, b) => state.layers.findIndex((l) => l.id === a) - state.layers.findIndex((l) => l.id === b)); commit(); },

    addAttack: () => {
      const a = {
        id: IO.uid('a_'), name: IO.uniqueName('New attack step', state.attacks.map((x) => x.name)), tactic: '',
        impact: 3, probability: 3, means: 3, actors: Object.fromEntries(state.actors.map((x) => [x, 0])),
      };
      state.attacks.push(a);
      filters.attacks = '';
      commit();
      const inp = $view.querySelector(`input[data-id="${a.id}"][data-f="name"]`);
      if (inp) { inp.scrollIntoView({ block: 'center' }); inp.select(); }
    },
    delAttack: (el) => {
      const a = attackById(el.dataset.id);
      if (!confirm(`Delete attack "${a.name}"?`)) return;
      state.attacks = state.attacks.filter((x) => x !== a);
      delete state.mapping[a.id];
      ui.keepScroll = true;
      commit();
    },
    addActor: () => {
      const name = promptName('New threat actor name', '', state.actors);
      if (!name) return;
      state.actors.push(name);
      for (const a of state.attacks) a.actors[name] = 0;
      commit();
    },
    renameActor: (el) => {
      const old = el.dataset.x;
      const name = promptName('Rename threat actor', old, state.actors);
      if (!name || name === old) return;
      state.actors[state.actors.indexOf(old)] = name;
      for (const a of state.attacks) { a.actors[name] = a.actors[old]; delete a.actors[old]; }
      state.view.actors = state.view.actors.map((x) => (x === old ? name : x));
      commit();
    },
    delActor: (el) => {
      const x = el.dataset.x;
      if (!confirm(`Remove actor "${x}"?`)) return;
      state.actors = state.actors.filter((y) => y !== x);
      for (const a of state.attacks) delete a.actors[x];
      state.view.actors = state.view.actors.filter((y) => y !== x);
      commit();
    },

    addDefense: () => {
      const d = { id: IO.uid('d_'), name: IO.uniqueName('New defense', state.defenses.map((x) => x.name)), category: '' };
      state.defenses.push(d);
      for (const l of state.layers) l.values[d.id] = IO.blankValues(state.zones);
      filters.defenses = '';
      commit();
      const inp = $view.querySelector(`input[data-id="${d.id}"][data-f="name"]`);
      if (inp) { inp.scrollIntoView({ block: 'center' }); inp.select(); }
    },
    delDefense: (el) => {
      const d = defenseById(el.dataset.id);
      if (!confirm(`Delete defense "${d.name}" from every layer?`)) return;
      state.defenses = state.defenses.filter((x) => x !== d);
      for (const l of state.layers) delete l.values[d.id];
      for (const row of Object.values(state.mapping)) delete row[d.id];
      ui.keepScroll = true;
      commit();
    },
    addZone: () => {
      const name = promptName('New zone name', '', state.zones);
      if (!name) return;
      state.zones.push(name);
      for (const l of state.layers) for (const v of Object.values(l.values)) v.zones[name] = 0;
      commit();
    },
    renameZone: (el) => {
      const old = el.dataset.z;
      const name = promptName('Rename zone', old, state.zones);
      if (!name || name === old) return;
      state.zones[state.zones.indexOf(old)] = name;
      for (const l of state.layers) for (const v of Object.values(l.values)) { v.zones[name] = v.zones[old]; delete v.zones[old]; }
      state.view.zones = state.view.zones.map((x) => (x === old ? name : x));
      commit();
    },
    delZone: (el) => {
      const z = el.dataset.z;
      if (!confirm(`Remove zone "${z}" from every layer?`)) return;
      state.zones = state.zones.filter((y) => y !== z);
      for (const l of state.layers) for (const v of Object.values(l.values)) delete v.zones[z];
      state.view.zones = state.view.zones.filter((x) => x !== z);
      if (!state.view.zones.length && state.zones.length) state.view.zones = [state.zones[0]];
      commit();
    },

    editLayer: (el) => { ui.editLayer = el.dataset.id; render(); },
    dupLayer: () => {
      const src = layerById(ui.editLayer);
      const name = promptName('Name of the new layer (e.g. a project)', IO.uniqueName(src.name + ' — copy', state.layers.map((l) => l.name)), state.layers.map((l) => l.name));
      if (!name) return;
      const l = { id: IO.uid('l_'), name, values: JSON.parse(JSON.stringify(src.values)) };
      state.layers.push(l);
      state.view.compare.push(l.id);
      ui.editLayer = l.id;
      commit();
    },
    newLayer: () => {
      const name = promptName('Name of the new layer', IO.uniqueName('New layer', state.layers.map((l) => l.name)), state.layers.map((l) => l.name));
      if (!name) return;
      const values = Object.fromEntries(state.defenses.map((d) => [d.id, IO.blankValues(state.zones)]));
      const l = { id: IO.uid('l_'), name, values };
      state.layers.push(l);
      state.view.compare.push(l.id);
      ui.editLayer = l.id;
      commit();
    },
    renameLayer: () => {
      const l = layerById(ui.editLayer);
      const name = promptName('Rename layer', l.name, state.layers.map((x) => x.name));
      if (!name) return;
      l.name = name;
      commit();
    },
    delLayer: () => {
      const l = layerById(ui.editLayer);
      if (state.layers.length < 2 || !confirm(`Delete layer "${l.name}"?`)) return;
      state.layers = state.layers.filter((x) => x !== l);
      state.view.layers = state.view.layers.filter((x) => x !== l.id);
      state.view.compare = state.view.compare.filter((x) => x !== l.id);
      if (!state.view.layers.length) state.view.layers = [state.layers[0].id];
      ui.editLayer = state.layers[0].id;
      commit();
    },

    cell: (el, e) => {
      const k = CELLS[el.dataset.kind];
      const n = k.max - k.min + 1;
      setCell(el, k.min + ((k.get(el) - k.min + (e && e.shiftKey ? n - 1 : 1)) % n));
    },

    exportJSON: () => download(`mire-${stamp()}.json`, JSON.stringify(state, null, 2), 'application/json'),
    exportXLSX: () => {
      if (!window.XLSX) return toast('Spreadsheet library not loaded');
      const h = IO.headers(state);
      const wb = XLSX.utils.book_new();
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(IO.attacksTable(state), { header: h.attacks }), 'Attacks');
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(IO.defensesTable(state), { header: h.defenses }), 'Defenses');
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(IO.mappingTable(state), { header: h.mapping }), 'Mapping');
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(resultsRows()), 'Results');
      XLSX.utils.book_append_sheet(wb, XLSX.utils.json_to_sheet(defenseResultRows()), 'Defense ranking');
      XLSX.writeFile(wb, `mire-${stamp()}.xlsx`);
    },
    exportCSV: (el) => {
      const t = el.dataset.t;
      const h = IO.headers(state);
      const csv = {
        attacks: () => IO.csvStringify(IO.attacksTable(state), h.attacks),
        defenses: () => IO.csvStringify(IO.defensesTable(state), h.defenses),
        mapping: () => IO.csvStringify(IO.mappingTable(state), h.mapping),
        results: () => IO.csvStringify(resultsRows()),
      }[t]();
      download(`mire-${t}-${stamp()}.csv`, '﻿' + csv, 'text/csv');
    },
    loadDefaults: () => { if (confirm('Replace the current model with the default dataset?')) setState(DEF.build(), 'Default dataset loaded'); },
    blank: () => {
      if (!confirm('Start from an empty model? Export first if you want to keep the current one.')) return;
      setState({ actors: [], zones: ['Zone 1'], attacks: [], defenses: [], layers: [{ id: 'l_base', name: 'Baseline', values: {} }], mapping: {} }, 'Blank model ready');
    },
  };

  /* ---------------- editing (no full re-render, keeps focus) ---------------- */
  function onEdit(el) {
    const id = el.dataset.id;
    const f = el.dataset.f;
    if (el.dataset.edit === 'attack') {
      const a = attackById(id);
      if (f === 'name') {
        const name = el.value.trim();
        if (!name || state.attacks.some((x) => x !== a && x.name === name)) { el.value = a.name; return toast('Attack names must be unique and non-empty'); }
        a.name = name;
      } else if (f === 'tactic') a.tactic = el.value.trim();
    } else if (el.dataset.edit === 'defense') {
      const d = defenseById(id);
      if (f === 'name') {
        const name = el.value.trim();
        if (!name || state.defenses.some((x) => x !== d && x.name === name)) { el.value = d.name; return toast('Defense names must be unique and non-empty'); }
        d.name = name;
      } else if (f === 'category') d.category = el.value.trim();
    }
    commit(false);
  }

  /* ---------------- import ---------------- */
  async function readFile(file) {
    const name = file.name.toLowerCase();
    const label = file.name.replace(/\.[^.]+$/, '');
    if (name.endsWith('.json')) {
      const obj = JSON.parse(await file.text());
      if (!obj || !Array.isArray(obj.attacks || obj.defenses)) throw new Error(`${file.name}: not a MIRE JSON export`);
      return { label, json: obj };
    }
    if (name.endsWith('.xlsx') || name.endsWith('.xls')) {
      if (!window.XLSX) throw new Error('Spreadsheet library not loaded');
      const wb = XLSX.read(await file.arrayBuffer(), { type: 'array' });
      const tables = {};
      for (const sn of wb.SheetNames) {
        const rows = XLSX.utils.sheet_to_json(wb.Sheets[sn], { defval: '', raw: false });
        const byName = sn.trim().toLowerCase();
        const kind = ['attacks', 'defenses', 'mapping'].includes(byName) ? byName : /result|ranking/.test(byName) ? null : IO.classify(rows);
        if (kind && rows.length) tables[kind] = rows;
      }
      return { label, tables };
    }
    const rows = IO.csvParse(await file.text());
    const kind = IO.classify(rows);
    if (!kind) throw new Error(`${file.name}: unrecognised table headers`);
    return { label, tables: { [kind]: rows } };
  }
  async function importFiles(files) {
    if (!files.length) return;
    const mode = ui.importMode;
    let next = state;
    try {
      const parsed = await Promise.all([...files].map(readFile));
      if (mode === 'replace') {
        const json = parsed.find((p) => p.json);
        if (json) next = IO.normalize(json.json);
        const merged = {};
        for (const p of parsed) if (p.tables) Object.assign(merged, p.tables);
        if (Object.keys(merged).length) next = IO.applyTables(next, merged, 'replace');
      } else {
        for (const p of parsed) {
          const tables = p.json ? { defenses: IO.defensesTable(IO.normalize(p.json)) } : p.tables;
          if (!tables.defenses) throw new Error(`${p.label}: no defense table found`);
          next = IO.applyTables(next, { defenses: tables.defenses }, 'layer', p.label);
        }
      }
      setState(next, `Imported ${files.length} file${files.length > 1 ? 's' : ''}`);
    } catch (e) {
      console.error(e);
      toast('Import failed: ' + e.message);
    }
  }
  function bindDrop() {
    const drop = document.getElementById('drop');
    const input = document.getElementById('fileIn');
    input.addEventListener('change', () => { const files = [...input.files]; input.value = ''; importFiles(files); });
    drop.addEventListener('dragover', (e) => { e.preventDefault(); drop.classList.add('over'); });
    drop.addEventListener('dragleave', () => drop.classList.remove('over'));
    drop.addEventListener('drop', (e) => {
      e.preventDefault();
      drop.classList.remove('over');
      importFiles([...e.dataTransfer.files]);
    });
  }

  /* ---------------- wiring ---------------- */
  document.getElementById('tabs').addEventListener('click', (e) => {
    const b = e.target.closest('button[data-tab]');
    if (b) go(b.dataset.tab);
  });
  $view.addEventListener('click', (e) => {
    const el = e.target.closest('[data-act]');
    if (el && actions[el.dataset.act] && !el.disabled) actions[el.dataset.act](el, e);
  });
  $view.addEventListener('keydown', (e) => {
    const el = e.target.closest('td.cell[data-kind]');
    if (!el) return;
    const k = CELLS[el.dataset.kind];
    if (e.key === ' ' || e.key === 'Enter') { e.preventDefault(); actions.cell(el, e); }
    else if (/^[0-9]$/.test(e.key) && Number(e.key) >= k.min && Number(e.key) <= k.max) { e.preventDefault(); setCell(el, Number(e.key)); }
    else if (e.key === 'Delete' || e.key === 'Backspace') { e.preventDefault(); setCell(el, k.min); }
  });
  $view.addEventListener('change', (e) => {
    const el = e.target;
    if (el.dataset.edit) return onEdit(el);
    if (el.dataset.view === 'layer') { state.view.layers = [el.value]; return commit(); }
    if (el.dataset.view === 'cert') { state.view.cert = el.checked; return commit(); }
    if ('imode' in el.dataset) ui.importMode = el.value;
  });
  $view.addEventListener('input', (e) => {
    if (e.target.dataset.filter) applyFilter(e.target);
  });
  window.addEventListener('hashchange', () => go(location.hash.slice(1)));
  window.addEventListener('storage', (e) => { if (e.key === KEY) { state = load(); render(); } });

  // theme
  const themeBtn = document.getElementById('themeBtn');
  try { const t = localStorage.getItem('mire.theme'); if (t) document.documentElement.dataset.theme = t; } catch (e) { /* ignore */ }
  themeBtn.addEventListener('click', () => {
    const dark = document.documentElement.dataset.theme
      ? document.documentElement.dataset.theme === 'dark'
      : matchMedia('(prefers-color-scheme: dark)').matches;
    document.documentElement.dataset.theme = dark ? 'light' : 'dark';
    try { localStorage.setItem('mire.theme', document.documentElement.dataset.theme); } catch (e) { /* ignore */ }
  });

  // re-enable the XLSX buttons once the deferred library arrives
  window.addEventListener('load', () => { if (ui.tab === 'data') render(); });

  go(location.hash.slice(1) || 'dashboard');
})();
