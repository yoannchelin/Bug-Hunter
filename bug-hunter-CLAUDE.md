# CLAUDE.md — Bug Hunter

> Briefing pour reprendre ce projet dans une nouvelle session Claude ou Claude Code.
> Lis ce fichier **en entier** avant d'écrire la moindre ligne.

---

## 1. Le projet en une phrase

**Bug Hunter** répond à la question : *"où est-ce que ça a déjà bugué, et est-ce que ça risque de rebuger ?"*. Il exploite l'historique Git déjà ingéré par Archaeologist pour détecter les zones à répétition de bugs, les patterns d'erreurs silencieuses dans le code, et les fichiers avec un ratio fix/feature anormalement élevé. Il croise avec Blast Radius pour signaler : *"cette zone buggy impacte aussi 60 autres symboles"*.

Tout tourne **en local**, **sans LLM au cœur**, **sans API payante**. Le LLM côté client MCP présente les résultats.

---

## 2. Relation avec l'écosystème

Bug Hunter est le **4e agent**. Il dépend de :

| Agent | Ce que Bug Hunter lit |
|---|---|
| **Git Archaeologist** | `commits`, `file_commits`, `symbols`, `files`, `edges` |
| **Blast Radius** | `blast_metrics.risk_score`, `blast_metrics.transitive_in` |

Tables écrites par Bug Hunter : préfixées `hunter_*`. Jamais d'écriture dans les tables des autres.

---

## 3. Ce que Bug Hunter détecte

### Signal 1 — Churn de fix (historique Git)
Identifie les commits de **bugfix** via les mots-clés dans les messages : `fix`, `bug`, `hotfix`, `patch`, `regression`, `revert`, `issue`, `error`, `broken`, `crash`, `panic`.

Pour chaque fichier : `fix_ratio = fix_commits / total_commits`. Un ratio > 0.4 est un signal fort.

### Signal 2 — Patterns d'erreurs silencieuses (AST Go + analyse TS)
Go (via AST) :
- `err` assigné mais jamais vérifié (`err := f(); _ = err` ou simplement ignoré)
- `if err != nil { return }` sans log ni wrapping (l'erreur se perd)
- `recover()` sans re-panic ni log (panique avalée silencieusement)
- Goroutines lancées sans gestion d'erreur ni WaitGroup

TypeScript/JavaScript (analyse textuelle, skipe node_modules/dist/.next/test) :
- Bloc `catch` vide ou contenant seulement un commentaire
- `.catch(() => {})` — rejet de promesse avalé silencieusement
- Appel async non-awaité dans une fonction async (floating promise)
- `JSON.parse()` sans try-catch — lève SyntaxError sur input invalide
- Opérateur non-null assertion `!.` — bypass de la null safety TypeScript

### Signal 3 — Auteurs et bus factor
- Fichiers touchés par un seul auteur (bus factor 1) avec fort churn
- Fichiers dont le seul auteur a arrêté de committer (départ probable)

### Signal 4 — Co-change dangereux
Fichiers qui sont toujours modifiés ensemble dans les commits de fix mais qui n'ont pas d'edge `calls`/`imports` dans le call graph — couplage implicite non modélisé, très risqué à modifier séparément.

---

## 4. Schema SQLite (`hunter_*`)

```sql
CREATE TABLE hunter_file_stats (
    file_id         INTEGER PRIMARY KEY,
    total_commits   INTEGER NOT NULL DEFAULT 0,
    fix_commits     INTEGER NOT NULL DEFAULT 0,
    fix_ratio       REAL NOT NULL DEFAULT 0,
    unique_authors  INTEGER NOT NULL DEFAULT 0,
    last_fix_ts     INTEGER NOT NULL DEFAULT 0,  -- unix seconds
    bus_factor      INTEGER NOT NULL DEFAULT 1,
    risk_score      REAL NOT NULL DEFAULT 0
);
CREATE INDEX idx_hunter_fix_ratio ON hunter_file_stats(fix_ratio DESC);

CREATE TABLE hunter_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id     INTEGER,
    symbol_id   INTEGER,
    kind        TEXT NOT NULL,
    -- 'fix_hotspot'        : fichier avec fix_ratio élevé
    -- 'silent_error'       : erreur ignorée ou avalée dans le code
    -- 'bus_factor_1'       : un seul auteur, auteur inactif
    -- 'implicit_coupling'  : co-change sans edge dans le graph
    severity    TEXT NOT NULL,
    message     TEXT NOT NULL,
    path        TEXT NOT NULL,
    line        INTEGER NOT NULL DEFAULT 0,
    blast_radius INTEGER NOT NULL DEFAULT 0,
    blast_risk   REAL NOT NULL DEFAULT 0
);
CREATE INDEX idx_hunter_findings_sev ON hunter_findings(severity, blast_risk DESC);

CREATE TABLE hunter_cochange (
    file_a      INTEGER NOT NULL,
    file_b      INTEGER NOT NULL,
    co_commits  INTEGER NOT NULL DEFAULT 0,  -- fois modifiés ensemble dans un fix
    has_edge    INTEGER NOT NULL DEFAULT 0,  -- 1 si edge dans le call graph
    PRIMARY KEY (file_a, file_b)
);

CREATE TABLE hunter_meta (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);
```

---

## 5. Les 4 outils MCP

| Tool | Input | Output |
|---|---|---|
| `hotspot_files` | `limit?`, `min_fix_ratio?` | Top fichiers par fix_ratio × blast_radius — les plus dangereux à toucher |
| `silent_errors` | `path?`, `limit?` | Patterns d'erreurs silencieuses dans le code, par fichier ou global |
| `implicit_couplings` | `limit?` | Paires de fichiers toujours modifiés ensemble mais sans edge dans le graph |
| `bug_risk_for_change` | `files[]` ou `diff` | Étant donné une liste de fichiers/diff, quels bugs historiques suggèrent un risque |

---

## 6. Layout du projet

```
cmd/
  hunter/         CLI : `hunter scan | hotspots | findings`
  hunter-mcp/     Binaire MCP stdio
internal/
  store/          Ouvre DB archaeo, ajoute hunter_*, lit blast_metrics
  gitanalysis/    Analyse commits : classification fix/feature, auteurs, co-change
  codeanalysis/   Analyse AST : silent errors, error handling patterns
  findings/       Agrège les signaux → hunter_findings
  mcpserver/      Les 4 outils MCP
```

---

## 7. Décisions architecturales

| Décision | Raison |
|---|---|
| **Heuristique de classification fix via mots-clés** | Pas de ML, pas d'API. Simple, rapide, ~85% de précision sur les repos réels. Configurable via une liste de mots extensible. |
| **Co-change sur les commits de fix uniquement** | Co-change sur tous les commits = bruit (refactors légitimes). Sur les commits de fix = signal fort de couplage caché. |
| **AST pour les silent errors** | `go vet` et `staticcheck` en font déjà une partie. Bug Hunter se concentre sur les patterns spécifiques aux bugs en production (recover silencieux, goroutines non surveillées) que les linters standard ne catchent pas tous. |
| **Bus factor = 1 seulement** | Au-delà, le risque est diffus. Bus factor 1 avec auteur inactif = truck factor réel. |
| **Blast radius optionnel** | Fonctionne sans Blast. Si `blast_metrics` est vide, les findings sont listés sans pondération risk. |

---

## 8. Pièges à anticiper

- **Schéma réel d'Archaeologist ≠ schéma supposé** — la table `commits` a les colonnes `author`, `email`, `ts`, `subject` (PAS `author_name`, `author_ts`, `message`, `num_parents`). La table `blast_metrics` est indexée par `symbol_id` (PAS `file_id`) — agréger via `symbols` pour obtenir les métriques par fichier. La table `edges` utilise `src`/`dst` (PAS `from_symbol_id`/`to_symbol_id`).
- **Les commits de merge** — pas de colonne `num_parents`, on filtre par heuristique sur le sujet : `strings.HasPrefix(lower, "merge ")`.
- **Les fichiers générés** (`// Code generated`) — skip dans l'AST walker, sinon des milliers de faux positifs sur les `.pb.go`.
- **Les fichiers `_test.go`** — skip dans l'AST walker, les patterns `_ = err` sont intentionnels dans les tests.
- **`_ = someCall()` vs `_, err := call()`** — ne flaguer comme `ignored_error` que quand TOUS les LHS sont `_`. `if _, err := w.Write(...)` est correct.
- **`recover()` légitime** — `if r := recover(); r != nil { log... }` est correct. Ne flaguer que `recover()` comme statement nu (ExprStmt sans capture).
- **`return nil, err`** n'est PAS un `lost_error` — l'erreur est propagée. Flaguer seulement `return` nu (named return) ou `return ..., nil` sans `err`.
- **Le co-change peut générer une table massive** sur les gros repos (N² paires de fichiers). Seuil : co-change ≥ 3 fois dans des commits de fix.
- **Blast metrics absents** — fonctionne sans. Si `blast_metrics` est vide, findings listés avec blast_risk=0.
- **Clone superficiel** — si un repo n'a qu'1 commit, les signaux git sont absents. Seule l'analyse AST fonctionne.
- **Logs sur stderr uniquement** dans `hunter-mcp`.

---

## 9. État d'implémentation

Tout est implémenté et testé sur les deux DB d'Archaeologist disponibles.

```
internal/store/       store.go + queries.go  — DB layer complet
internal/gitanalysis/ classify.go + analyze.go  — classification + stats + co-change
internal/findings/    findings.go  — fix_hotspot, bus_factor_1, implicit_coupling
internal/codeanalysis/ast.go         — ignored_error, swallowed_panic, unguarded_goroutine, lost_error
internal/codeanalysis/typescript.go  — swallowed_exception (catch/promise), floating_promise, unsafe_assertion
internal/mcpserver/   server.go  — 4 outils MCP (JSON-RPC 2.0 stdio)
cmd/hunter/           main.go  — CLI : scan / hotspots / findings / status
cmd/hunter-mcp/       main.go  — binaire MCP
```

---

## 10. Commandes utiles

```bash
hunter scan --db /path/to/.archaeo/index.db --repo /path/to/repo
hunter scan --db /path/to/.archaeo/index.db --repo /path/to/repo --no-ast   # skip Go AST
hunter scan --db /path/to/.archaeo/index.db --repo /path/to/repo --no-ts    # skip TS/JS
hunter hotspots --db /path/to/.archaeo/index.db --top 20
hunter findings --db /path/to/.archaeo/index.db --severity high
hunter findings --db /path/to/.archaeo/index.db --kind unsafe_assertion

hunter-mcp --db /path/to/.archaeo/index.db
```

---

## 11. Comment reprendre

1. Lis ce fichier en entier — notamment la section 8 sur le schéma réel.
2. Vérifie que Git Archaeologist a indexé le git history (0 commits = clone superficiel, seule l'AST marchera).
3. Lance `hunter scan --db ... --repo ...` puis `hunter findings --db ... --severity high`.
4. Mets à jour ce fichier si tu prends une décision archi ou découvres un piège.
