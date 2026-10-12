# Installation and the dependency map

The short version is in the [README](../README.md#installation-and-dependencies): clone,
`pip install -e .`, keep the clone. This page holds the reasons and the full map.

## Why editable, and why keep the clone

The `-e` is not a style preference. `llm-scanner` and `llm-firewall` import their attack
corpus and guard implementations from `labs/vulnllm/`, which is deliberately not packaged
(see below), so they need the checkout on disk. From a plain non-editable wheel they stop
with an error naming the missing directory; before 2026-07-29 they died at `--help` with a
bare `ModuleNotFoundError` about a module the user never wrote. `prompt-injection-detect`
is the exception: the trained model ships as package data, so prediction works anywhere
and only `--train` needs the corpus.

That split is a contract, not an accident, so it is tested from a real non-editable
install in `tests/test_wheel_install.py` and in CI's `wheel` job. The `test` job cannot
see it: it installs with `-e`, which keeps the checkout on disk and makes the lookup
succeed every time.

## The distribution name

The distribution is `wrg-ai-security-toolkit`, with the prefix. The unprefixed
`ai-security-toolkit` on PyPI is a different project by a different author. It is also a
red-team AI security framework, which is why the collision is worth flagging. If you
install without the prefix you get their code, not this. The repository, the clone
directory and the three commands keep their unprefixed names; only the distribution
carries the prefix.

## The dependency map

The "zero-dependency" claim is specific, so here is the whole map. Each extra is needed
only by the directory next to it:

| Component | Install | Pulls in | Why |
|---|---|---|---|
| `tools/`: detector, scanner, firewall | `pip install -e .` | *nothing* | Python stdlib only |
| `labs/vulnllm/`: the lab and its 10 challenges | *(none)* | *nothing* | stdlib only; run in place |
| `labs/rag-security/` | `pip install -e ".[rag]"` | `chromadb`, `sentence-transformers` | a RAG lab needs a vector store *and* an embedding model |
| `huggingface-space/` | `pip install -e ".[hf]"` | `gradio` | Two front-ends over the same detector. `index.html` is the deployed Static Space: Pyodide in the browser, `micropip` installs this package from PyPI, nothing leaves the page. `app.py` is the local Gradio variant, and needs the extra. Neither reimplements the detector. |
| `ctf-writeups/agent-odin/` | `pip install -e ".[ctf]"` | `requests` | the three ODIN solvers; the Gandalf one is stdlib |
| tests, lint, coverage | `pip install -e ".[dev]"` | `pytest`, `coverage`, `ruff` | measurement tools, not runtime deps |

Two rows were wrong until 2026-07-29, both in the direction that matters. The `rag` extra
listed `chromadb` alone while the lab also needs `sentence-transformers`
(`VulnerableRAG.__init__`), so the documented command produced a lab that died on setup.
The `ctf` row did not exist at all, which made this table's claim to be "the whole map"
false by exactly the one entry that pulls a real dependency.

`dependencies = []` in `pyproject.toml` is the machine-readable form of the first two
rows: the claim is checkable by a resolver, not just asserted in prose.

`labs/` is intentionally not packaged. It is a teaching lab meant to be read and run where
it sits, and its modules are reached through a `sys.path` insert rather than as a
distribution. Packaging it would imply an import contract this repository does not offer
yet.
