# warden

*A gated AI execution runtime. Models suggest. The system decides. Execution is gated.*

[![ci](../../actions/workflows/ci.yml/badge.svg)](../../actions/workflows/ci.yml)

Most AI agents hand a model the keys. **warden** doesn't. A language model only
*proposes* a plan as strict JSON. Everything after that — validation, risk
analysis, the final verdict, the dry run and the sandboxed execution — is
plain, deterministic, testable code. A human approves anything that changes state,
and every run is written to a tamper-evident audit log.

```
$ warden run 'make folder archive then write "old stuff" to archive/old.txt'

── dry run ─────────────────────────────────────────
intent:  multi_step
verdict: require_confirmation  (irreversible: irreversible action(s): ['write_file'])
  ✓ step_1   make_dir     archive                  [low] will create directory
  ✓ step_2   write_file   archive/old.txt          [medium] will create new file with 9 chars
────────────────────────────────────────────────────
approve? [y/N] y

executed at execute: executed 2 step(s)
```

## How a request flows

```
input
  → guard            length, encoding, prompt-injection & shell-injection checks — before any model sees it
  → primary planner  natural language → JSON plan (retried on bad JSON / schema; never on "cannot_plan")
  → analysis pass 1  facts only: categories, unknown & irreversible actions, state change
  → validator        only for state-changing plans: a second, independent model call on the ORIGINAL input
  → comparator       plans disagree → hard stop. No auto-resolution; a human decides
  → analysis pass 2  interpretation only: destructive wording, intent/action mismatch (pass-1 facts are frozen)
  → policy           proceed | require_confirmation | reject — first matching rule wins, no model involved
  → dry run          each step pre-flighted against the real filesystem ("will OVERWRITE 312 bytes")
  → approval         human; read-only plans can be auto-approved with --auto-read, writes never are
  → executor         sandboxed to one workspace directory; stops at the first failing step
  → audit            SHA-256 hash-chained SQLite record of everything above
```

### Policy rules (in order)

| # | Rule | Verdict |
|---|------|---------|
| 1 | Any unknown action | reject |
| 2 | A step with no arguments (unbounded scope) | reject |
| 3 | Declared intent contradicts the actions (e.g. `read_only` that deletes) | confirm |
| 4 | Irreversible action (`write_file`, `delete_file`) | confirm |
| 5 | Plan declared `destructive` | confirm |
| 6 | Destructive wording (`purge`, `wipe`, `reset`…) on a state-changing plan | confirm |
| 7 | Multi-step plan that changes state | confirm |
| 8 | Any state change | confirm |
| — | Otherwise (read-only) | proceed |

Loss aversion is the design principle: asking when it wasn't needed is always
cheaper than acting when it was wrong.

### Safety properties

- **Sandbox** — every path resolves inside the workspace. Absolute paths, `..`,
  and symlinks that point outside are refused. The runtime's own `.warden/`
  directory is off-limits to plans.
- **Soft deletes** — `delete_file` moves files to `workspace/.warden/trash/`.
- **Closed vocabulary** — the model can only use the seven actions in
  [`warden/actions.py`](warden/actions.py) (plus aliases like `rm`, `cat`).
  Anything else is unknown and rejected. There is no shell action, on purpose.
- **Independent redundancy** — the validator never sees the primary's output.
  Aliases are normalised before comparing, but there is no fuzzy matching.
- **Tamper-evident log** — editing or deleting any sealed row breaks the chain
  from that point; `warden verify` reports where. (Like any hash chain without an
  external anchor, it cannot detect truncation of the newest rows.)

## Quick start

```bash
git clone <your-repo-url> warden && cd warden
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

mkdir -p workspace && echo "TODO: call bank" > workspace/notes.txt

warden --auto-read run read notes.txt
warden run 'write "hello" to greeting.txt'
warden shell                 # interactive
warden log                   # recent runs
warden verify                # check the audit chain
warden actions               # the action vocabulary
pytest -q                    # 50 tests, no model required
```

By default warden uses a small **mock planner** (keyword rules) so you can try
everything without a GPU. It understands `read X`, `list X`, `search for Y in X`,
`write "…" to X`, `append "…" to X`, `make folder X`, `delete X`, chained with `then`.

### Using a real local model (Ollama)

```bash
ollama pull qwen2.5:7b-instruct-q4_K_M
ollama create warden-primary   -f models/Modelfile.primary
ollama create warden-validator -f models/Modelfile.validator

warden --planner ollama --model warden-primary --validator-model warden-validator shell
```

The planning prompt lives in [`warden/prompts/planner.txt`](warden/prompts/planner.txt).

## Layout

```
warden/
  guard.py        input guard
  planner.py      Ollama + mock planners, retry policy
  schema.py       plan JSON schema + validator
  actions.py      action registry (closed vocabulary)
  analysis.py     two-pass analysis
  comparator.py   primary vs validator comparison
  policy.py       decision engine
  executor.py     sandboxed preflight + execution
  audit.py        hash-chained audit log
  pipeline.py     sequencing only
  cli.py          command-line interface
tests/            unit + end-to-end tests
models/           Ollama Modelfiles
```

## Roadmap

- [ ] Plan-level args typing per action (schema per action)
- [ ] Dedicated response model for friendlier natural-language replies
- [ ] Optional third "last resort" planner (e.g. a hosted model) for repeated schema failures
- [ ] Undo for reversible actions; restore from trash
- [ ] Web / chat transports

## Credits

Inspired by the architecture of [IRIS](https://github.com/nikuhkid/iris) by nikuhkid.
warden is an independent implementation.

## License

MIT
