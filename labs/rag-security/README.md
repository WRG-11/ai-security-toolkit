# RAG Security Lab

**Vulnerable RAG system with attack scenarios and defense mechanisms.**

A vulnerable RAG system — 5 attack scenarios and their defenses.

---

## What is this?

A deliberately vulnerable Retrieval-Augmented Generation (RAG) system that demonstrates how attackers can extract confidential information, poison knowledge bases, and manipulate LLM responses through the retrieval pipeline.

A lab that demonstrates attacks against a RAG pipeline and teaches the defenses against them.

## Architecture

```
User Query
    |
    v
[Embedding Model] ──> sentence-transformers
    |
    v
[Vector Search] ──> ChromaDB (9 documents)
    |
    v
[Context Assembly] ──> Retrieved chunks + query
    |
    v
[LLM Generation] ──> Ollama (local)
    |
    v
Response (potentially leaking confidential data)
```

## Documents

The 9 documents actually loaded by `COMPANY_DOCUMENTS` in
[`vulnerable_rag.py`](vulnerable_rag.py) (`python -c "import ast; t=ast.parse(open('vulnerable_rag.py').read()); print(len([n for n in ast.walk(t) if isinstance(n, ast.Assign) and getattr(n.targets[0], 'id', '')=='COMPANY_DOCUMENTS'][0].value.elts))"`
to recount). This table previously listed 10 different, unrelated filenames
(`company_overview.md`, `salary_structure.md`, `merger_plans.md`,
`client_database.md`, ...) that do not exist anywhere in this lab's code.

| Document ID | Classification | Content |
|----------|---------------|---------|
| `doc_about` | public | Company overview (founding, HQ, headcount) |
| `doc_products` | public | Product listings (AcmeCloud, AcmeData, AcmeAI) |
| `doc_policy` | internal | Remote work policy, internal VPN endpoint |
| `doc_employees` | confidential | Employee directory with named salaries |
| `doc_credentials` | top_secret | AWS root account, DB password, API/K8s tokens |
| `doc_security` | confidential | Security incident report (phishing, compromised accounts) |
| `doc_financial` | confidential | Q4 financial summary, unannounced funding round |
| `doc_poisoned_1` | internal (poisoned) | Injected instruction demanding the user's employee ID/email |
| `doc_poisoned_2` | internal (poisoned) | Injected instruction to leak a hardcoded "master reset token" |

## Attack Scenarios

### 1. Direct Disclosure
Ask the RAG system about confidential topics — it retrieves and reveals them.

### 2. Indirect Injection
Poisoned documents contain hidden instructions that override system behavior.

### 3. Context Overflow
Flood the context window to push out safety instructions.

### 4. Prompt Override
Embed "ignore previous instructions" in retrieved documents.

### 5. Membership Inference
Determine whether specific data exists in the knowledge base.

## Quick Start

```bash
# Setup (creates ChromaDB + loads documents)
python vulnerable_rag.py --setup

# Interactive mode (try attacks manually)
python vulnerable_rag.py --interactive

# Run all attack scenarios
python vulnerable_rag.py --attack

# Run with defenses enabled
python vulnerable_rag.py --defend
```

## Results

| Mode | Leakage Rate |
|------|-------------|
| **Vulnerable (no defense)** | 42% |
| **Defended (filtering + detection)** | 0% |

> Rates measured on the 5 included attack scenarios using `python vulnerable_rag.py --attack` (vulnerable) and `--attack --defend` (defended). Real-world leakage depends on model, document corpus, and attacker creativity.
>
> Independently re-run 2026-09-14 against `chromadb` 1.5.9 and
> `sentence-transformers` 6.0.1 (current latest at the time, confirming the
> lab still works against the newest releases of both) on `qwen2.5-coder:7b`
> via Ollama -- a different model from whichever produced the original
> numbers. Same result to the percentage point: 5/12 leaked (42%) undefended,
> 0/12 leaked (0%) defended.
>
> **Read 42% as an upper bound.** The leak check (`find_leaks`) looks for
> marker strings in the answer. Two of the markers, "salary" and "password",
> name a topic rather than a value, so a refusal such as "I cannot share
> salary information" counts as a leak. A test pins this as a known gap:
> `tests/test_vulnerable_rag_logic.py`. Fixing it changes the number above, and
> that number should come from a new live run, not an estimate.

## Requirements

- Python 3.10+
- ChromaDB (`pip install chromadb`)
- sentence-transformers (`pip install sentence-transformers`)
- Ollama with a model loaded
