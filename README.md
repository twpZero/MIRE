# MIRE — Measure Impact of Residual Exposure

MIRE maps a company's **defenses** against **attack steps** to find weak points, so architects, CISOs and CERTs can address them or formally accept them. It also compares the **residual risk** of budget options: should the money go to project X or project Y?

It is a static web app (HTML + vanilla JS, no build step) meant to be hosted on GitHub Pages. Everything runs in the browser. Nothing is uploaded, and your work is saved in the browser's local storage.

## Features

| Tab | What it does |
|---|---|
| **Dashboard** | Pick threat actors, a zone, one or more defense layers, and the CERT view. Shows the attacks ranked by MIRE, the defenses ranked by blocking score and unique reduction, and an attack × zone heatmap. |
| **Attacks** | Attack steps or means. Impact, Probability and Means are scored 1–5. Threat actor columns are 0/1. You can add lines and actors, rename them and delete them. |
| **Defenses** | Security tooling and OS features. Cost, Operational difficulty and Lack of efficiency are scored 1–5. Zone columns hold the missing coverage of the control in each zone (0–5, 5 = not deployed). Layers let you keep several defense sets: sites, subsidiaries, projects. |
| **Mapping** | The attack × defense matrix: how each defense acts on each attack (5D: 1 Deny · 2 Defer · 3 Degrade · 4 Disrupt · 5 Detect, empty = no effect). Blind spots are highlighted. |
| **Compare** | Puts layers side by side, for example *Baseline* vs *Project X* vs *Project Y*. Shows the total and per-attack residual exposure. |
| **Import / Export** | JSON (full model), XLSX (one sheet per table plus results) and CSV (one table per file). Defense files can be imported as additional layers. |
| **Method** | The formulas, in the app. |

## Model

```
A(attack)        = Impact × Probability × Means                     1 … 125
w(attack)        = max of selected actor flags (adding actors = max)  0 … 1   (1 when no actor selected)
D(attack, defense, zone) = Cost × Difficulty × Lack × Missing(zone) × Action(attack, defense)
CERT view                = Lack × Missing(zone) × Action
D(attack, zone)  = min D over mapped defenses deployed in the zone (adding defenses = min)
                   D_max = 3125 (125 in CERT view) when no defense covers it (unmitigated)
MIRE             = A × w × D(attack, zone)
```

* **Action (mapping cell, 5D):** 1 Deny · 2 Defer · 3 Degrade · 4 Disrupt · 5 Detect · 0/empty = no effect on that attack.
* **Missing coverage (zone cell):** 1 fully covered … 4 mostly missing · **5 = not deployed (maximum risk)**. A defense that is not deployed in a zone is ignored there, so the zone keeps D_max unless another control covers it.
* **All zones:** the mean MIRE over the zones. The weakest zone and its best control are reported next to it.
* **Attack ranking:** attacks sorted by MIRE, highest residual exposure first.
* **Defense ranking:**
  * *Unique reduction* is how much Σ MIRE grows if the defense is removed.
  * *Blocking score* is Σ A·w·(D_max − D)/D_max, the risk the defense absorbs on its own.
* **CERT view:** drops cost and difficulty, so it shows what you should do whether or not you can afford it.
* **Multi-layer:** select several layers on the dashboard to merge them line by line with the **weakest** setting. Every score and zone takes the max, so a zone counts as not deployed if any layer lacks the defense there.

## Default dataset

* 35 attack steps covering the 14 MITRE ATT&CK Enterprise tactics.
* 4 actors: APT29, FIN6, FIN12 and Pentest Oracle.
* 29 common defenses: network, endpoint, identity, detection, OS features and process.
* 5 zones: Perimeter, Endpoint, Datacenter, Cloud and Identity.
* 3 layers: *Baseline*, *Project X — EDR rollout* and *Project Y — Identity (CA + PAM)*.

All the scores and actor flags are **illustrative**. Review them against your own CTI and environment before you rely on the results. *Import / Export → Restore default dataset* brings them back.

## File formats

Exports and imports use the same table layouts. CSV and XLSX tables are recognised by their headers:

* **Attacks:** `Attack, Tactic, Impact, Probability, Means, <actor 1>, <actor 2>, …`
* **Defenses:** `Layer, Defense, Category, Cost, Operational Difficulty, Lack of Efficiency, <zone 1>, …`
  * Zone cells hold missing coverage `1–5`. `5`, an empty cell or text means not deployed.
  * `Layer` is optional. Without it, the file name is used as the layer name.
* **Mapping:** `Attack, <defense 1>, <defense 2>, …` with the action `0–5` or `Deny / Defer / Degrade / Disrupt / Detect` in each cell.

JSON is the full state, including all layers and view settings. Data saved by the first version of the app (5D in the zone cells) is migrated automatically when loaded.

## Run locally

```bash
npm start          # serves the folder on http://localhost:8080
npm test           # model + import/export unit tests (Node ≥ 18)
```

You can also open `index.html` directly from disk. Only XLSX needs the network, to load SheetJS from cdnjs.

## Publish on GitHub Pages

The repository ships with `.github/workflows/pages.yml`, which runs the tests and then deploys the site on every push to `main`.

1. In the repository, open **Settings → Pages**.
2. Set **Source** to **GitHub Actions**.
3. Merge to `main`. The site is published at `https://<user>.github.io/<repo>/`.

Alternatively, choose **Deploy from a branch** → `main` / root. The app needs no build step.

## Project layout

```
index.html          page shell
css/style.css       styles (light/dark)
js/model.js         pure MIRE computation (browser + Node)
js/defaults.js      default attacks, defenses, zones, layers, mapping
js/io.js            CSV parsing, table <-> state conversion, import logic
js/app.js           UI
tests/              node:test unit tests
```
