# RAG Security Lab

**Vulnerable RAG system with attack scenarios and defense mechanisms.**

Savunmasız RAG sistemi — 5 saldırı senaryosu ve savunma mekanizmaları.

---

## What is this? / Bu ne?

A deliberately vulnerable Retrieval-Augmented Generation (RAG) system that demonstrates how attackers can extract confidential information, poison knowledge bases, and manipulate LLM responses through the retrieval pipeline.

RAG pipeline'ına yönelik saldırıları gösteren ve savunma yöntemlerini öğreten bir lab ortamı.

## Architecture / Mimari

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

## Documents / Dokümanlar

| Document | Classification | Content |
|----------|---------------|---------|
| company_overview.md | PUBLIC | General company info |
| product_catalog.md | PUBLIC | Product listings |
| employee_handbook.md | INTERNAL | HR policies |
| salary_structure.md | INTERNAL | Compensation data |
| merger_plans.md | CONFIDENTIAL | M&A strategy |
| client_database.md | CONFIDENTIAL | Client PII |
| security_audit.md | CONFIDENTIAL | Vulnerability findings |
| api_keys.md | TOP SECRET | API credentials |
| poisoned_faq.md | POISONED | Injected malicious content |
| poisoned_policy.md | POISONED | Injected override instructions |

## Attack Scenarios / Saldırı Senaryoları

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

## Quick Start / Hızlı Başlangıç

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

## Results / Sonuçlar

| Mode | Leakage Rate |
|------|-------------|
| **Vulnerable (no defense)** | 42% |
| **Defended (filtering + detection)** | 0% |

## Requirements / Gereksinimler

- Python 3.10+
- ChromaDB (`pip install chromadb`)
- sentence-transformers (`pip install sentence-transformers`)
- Ollama with a model loaded
