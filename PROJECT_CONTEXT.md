# CS8.401 — POIS Project: Full Context & Summary

> Paste this into any new chat to give full context of everything built.  
> Open in VS Code and press `Ctrl+Shift+V` to preview — all math renders via KaTeX.

---

## Project Overview

**Course:** CS8.401 — Principles of Information Security  
**Assignments:** PA \#1 (OWF + PRG) and PA \#2 (PRF via GGM Tree)  
**Location:** `c:\Users\lenovo\Downloads\pois project\`  
**Status:** Fully implemented. 74/74 tests passing.

**Core concept — the Minicrypt Clique:** all five primitives are equivalent under polynomial-time reductions:

$$\text{OWF} \;\Longleftrightarrow\; \text{PRG} \;\Longleftrightarrow\; \text{PRF} \;\Longleftrightarrow\; \text{PRP} \;\Longleftrightarrow\; \text{MAC}$$

---

## Tech Stack

| Layer | Technology | Version |
|-------|-----------|---------|
| Frontend | React + Vite | React 19, Vite 8 |
| Backend | Python + FastAPI + Uvicorn | Python 3.14, FastAPI 0.135.2 |
| Testing | pytest | 9.0.2 |
| Analysis | matplotlib + numpy | 3.10.8 / 2.4.4 |
| Packages | pip + venv | — |

**Key restriction:** No external crypto libraries. Only `os.urandom` and Python built-in `int` allowed. AES-128 is implemented entirely from scratch.

---

## Directory Structure

```
pois project/
├── backend/
│   ├── pa1/
│   │   ├── owf.py           ← DLP-OWF + AES-OWF (AES from scratch)
│   │   ├── prg.py           ← HILL/GL PRG + OWF_from_PRG reduction
│   │   └── nist_tests.py    ← NIST SP 800-22: frequency, runs, serial
│   ├── pa2/
│   │   └── prf.py           ← GGM tree PRF + AES PRF + PRG_from_PRF
│   └── api/
│       └── main.py          ← FastAPI: 8 REST endpoints
├── frontend/src/
│   ├── App.jsx              ← 7 interactive panels, tab nav
│   ├── App.css              ← dark theme
│   └── api.js               ← fetch() wrappers
├── tests/
│   ├── test_pa1_owf.py      ← 16 tests
│   ├── test_pa1_prg.py      ← 17 tests
│   ├── test_pa1_nist.py     ← 14 tests
│   └── test_pa2_prf.py      ← 27 tests
├── venv/
├── requirements.txt
├── DEVLOG.md
└── PROJECT_CONTEXT.md       ← this file
```

---

## How to Run

```bash
# Backend (from project root)
venv/Scripts/python -m uvicorn backend.api.main:app --reload --port 8000

# Frontend (new terminal)
cd frontend && npm run dev

# Tests
venv/Scripts/python -m pytest tests/ -v
```

| URL | What |
|-----|------|
| http://localhost:5173 | React frontend UI |
| http://localhost:8000/docs | Swagger API docs |
| http://localhost:8000/health | Health check |

---

## PA \#1 — One-Way Function (OWF)

**File:** `backend/pa1/owf.py`

### DLP-based OWF

$$f(x) = g^x \bmod p$$

- $p$ = 256-bit safe prime (Oakley Group 1, RFC 2409), $\;g = 2$
- **Security:** Discrete Logarithm Problem — given $g^x \bmod p$, finding $x$ is computationally infeasible
- Input: non-negative integer $x$; Output: integer in $[1,\, p-1]$
- Multiplicative property: $g^{a+b} \bmod p = (g^a \bmod p)\cdot(g^b \bmod p)\bmod p$

### AES-based OWF

$$f(k) = \text{AES}_k\!\left(0^{128}\right) \oplus k$$

- AES-128 built 100% from scratch: SubBytes, ShiftRows, MixColumns, AddRoundKey, KeyExpansion
- GF$(2^8)$ arithmetic (`gmul`, `xtime`) for MixColumns
- NIST known-answer test verified:

$$\text{AES}_{0^{128}}\!\left(0^{128}\right) = \texttt{66e94bd4ef8a2c3b884cfa59ca342b2e} \;\checkmark$$

- FIPS 197 Appendix B vector verified $\checkmark$

### Signatures
```python
owf_dlp(x: int) -> int
owf_aes(k: bytes) -> bytes          # k must be 16 bytes
_aes128_encrypt_block(pt, key)      # raw AES (also used by PA2)
```

---

## PA \#1 — Pseudorandom Generator (PRG)

**File:** `backend/pa1/prg.py`

### HILL / Goldreich-Levin Construction

Given OWF $f : \{0,1\}^n \to \{0,1\}^n$, the PRG stretching $n$ bits to $n + \ell$ bits is:

$$G(x_0) \;=\; b(x_0) \;\Big\|\; b(x_1) \;\Big\|\; \cdots \;\Big\|\; b(x_\ell)$$

State iteration:

$$x_{i+1} = f(x_i)$$

Goldreich-Levin hard-core bit with fixed random vector $r$:

$$b(x_i) \;=\; \langle x_i,\, r \rangle \bmod 2 \;=\; \bigoplus_{j=1}^{n}\!\bigl(x_i^{(j)} \wedge r^{(j)}\bigr)$$

By the **Goldreich-Levin theorem**, no PPT adversary predicts $b(x_i)$ with probability $> \tfrac{1}{2} + \text{negl}(n)$ given $f(x_i)$.

### Classes
```python
PRG_AES(output_bits=256, r=None)   # AES-based OWF
PRG_DLP(output_bits=256, r=None)   # DLP-based OWF

prg.seed(s)             # s: bytes (AES) or int (DLP)
prg.next_bits(n) -> int # n pseudorandom bits as integer
prg.generate_bytes(n)   # n pseudorandom bytes

make_prg(mode="aes", output_bits=256)   # factory
```

### PRG $\Rightarrow$ OWF Reduction

Given PRG $G : \{0,1\}^n \to \{0,1\}^{2n}$, define:

$$f_G(s) \;=\; G(s)\bigl[0\,:\,n\bigr]$$

**Security:** Any efficient inverter $\mathcal{A}$ for $f_G$ gives a distinguisher $\mathcal{D}$ for $G$ with the same advantage — contradicting PRG security.

```python
OWF_from_PRG(prg).compute(seed) -> int
```

---

## PA \#1 — NIST SP 800-22 Tests

**File:** `backend/pa1/nist_tests.py`  
All pure Python — no scipy.

### Test 1: Frequency (Monobit) — NIST §2.1

$$S_n = \sum_{i=1}^{n}(2\epsilon_i - 1), \qquad s_{\text{obs}} = \frac{|S_n|}{\sqrt{n}}$$

$$P\text{-value} = \operatorname{erfc}\!\left(\frac{s_{\text{obs}}}{\sqrt{2}}\right) \;\geq\; 0.01 \;\Rightarrow\; \text{PASS}$$

### Test 2: Runs — NIST §2.3

Pre-condition: $\bigl|\pi - \tfrac{1}{2}\bigr| < \dfrac{2}{\sqrt{n}}$ where $\pi = \tfrac{\#\text{ones}}{n}$.

$$P\text{-value} = \operatorname{erfc}\!\left(\frac{\bigl|V_{\text{obs}} - 2n\pi(1-\pi)\bigr|}{2\sqrt{2n}\;\pi(1-\pi)}\right)$$

$V_{\text{obs}}$ = total number of runs (maximal blocks of identical bits).

> A perfectly alternating $010101\cdots$ sequence has $V_{\text{obs}} \approx n-1$ vs.\ expected $\approx \tfrac{n}{2}$ — it **correctly fails** this test. This is not a bug.

### Test 3: Serial ($m=2$) — NIST §2.11

$$\psi^2_m = \frac{2^m}{n}\sum_{\text{all }m\text{-bit patterns}}\!\bigl(\text{count}\bigr)^2 \;-\; n$$

$$\nabla\psi^2_m = \psi^2_m - \psi^2_{m-1}, \qquad \nabla^2\psi^2_m = \psi^2_m - 2\psi^2_{m-1} + \psi^2_{m-2}$$

$$P\text{-value} = \min\!\left[\,Q\!\left(2^{m-2},\,\tfrac{\nabla\psi^2_m}{2}\right),\; Q\!\left(2^{m-3},\,\tfrac{\nabla^2\psi^2_m}{2}\right)\right]$$

where $Q(a,x)$ = regularised upper incomplete gamma, computed via Lentz continued-fraction expansion (precision $< 10^{-12}$).

### Usage
```python
run_all_tests(prg, seed, n_bits=20000) -> list[dict]
run_tests_on_bytes(data: bytes)        -> list[dict]
# Each dict: {'test', 'p_value', 'pass', 'details'}
```

---

## PA \#2 — Pseudorandom Function (PRF) via GGM Tree

**File:** `backend/pa2/prf.py`

### GGM Tree Construction

Doubling PRG from our scratch AES:

$$G_0(k) = \text{AES}_k(1), \qquad G_1(k) = \text{AES}_k(2)$$

PRF on domain $\{0,1\}^\ell$ for input $x = b_1 b_2 \cdots b_\ell$:

$$F_k(b_1 b_2 \cdots b_\ell) \;=\; G_{b_\ell}\!\Bigl(G_{b_{\ell-1}}\!\bigl(\cdots G_{b_1}(k)\cdots\bigr)\Bigr)$$

Traverse a binary tree of depth $\ell$: go left ($G_0$) if $b_i = 0$, right ($G_1$) if $b_i = 1$.

**Security:** Any PRF distinguisher with advantage $\varepsilon$ implies a PRG distinguisher with advantage $\varepsilon / 2^\ell$.

### AES Plug-in PRF

$$F_k(x) = \text{AES}_k(x)$$

Secure by the **PRP–PRF switching lemma**: advantage difference between PRP and PRF is at most $\dbinom{q}{2}\!/\,2^n$ for $q$ queries.

### PRF $\Rightarrow$ PRG Reduction

Given PRF $F_k : \{0,1\}^n \to \{0,1\}^n$, treating $s$ as an $(n-1)$-bit string:

$$G_k(s) \;=\; F_k(s \;\|\; 0) \;\Big\|\; F_k(s \;\|\; 1)$$

Maps $(n-1)$ bits to $2n$ bits. Any distinguisher for $G_k$ directly implies a PRF adversary with the same advantage.

### Distinguishing Game

Adversary makes $q$ adaptive queries to either:
- **Real world:** oracle $F_k$ for secret $k$
- **Random world:** truly random function $R : \{0,1\}^n \to \{0,1\}^n$

A secure PRF gives statistical distance $\ll 0.1$ on LSB distributions. Verified: distance $< 0.15$ in tests.

### Signatures
```python
PRF_GGM(input_bits=8)
  .evaluate(k: bytes, x: int|bytes) -> bytes   # 16-byte output
  .__call__(k, x)

PRF_AES()
  .evaluate(k: bytes, x: int|bytes) -> bytes

PRG_from_PRF(prf=None, input_bits=8)
  .seed(k: bytes, s: int=0)
  .next_bits(n: int) -> int
  .generate_bytes(n: int) -> bytes

distinguishing_game(n_queries=20, input_bits=8) -> dict
```

---

## All Reductions Implemented

| Reduction | Formula | File / Class |
|-----------|---------|-------------|
| OWF $\to$ PRG | $G(x_0) = b(x_0) \| \cdots \| b(x_\ell)$ | `pa1/prg.py` — `PRG_AES`, `PRG_DLP` |
| PRG $\to$ OWF | $f_G(s) = G(s)[0:n]$ | `pa1/prg.py` — `OWF_from_PRG` |
| PRG $\to$ PRF | $F_k(b_1\cdots b_\ell) = G_{b_\ell}(\cdots G_{b_1}(k)\cdots)$ | `pa2/prf.py` — `PRF_GGM` |
| PRF $\to$ PRG | $G_k(s) = F_k(s\|0) \| F_k(s\|1)$ | `pa2/prf.py` — `PRG_from_PRF` |
| PRP $\to$ PRF | $F_k(x) = \text{AES}_k(x)$ | `pa2/prf.py` — `PRF_AES` |

---

## FastAPI Endpoints

**Base URL:** `http://localhost:8000` · **Docs:** `/docs`

```
POST /pa1/owf               { mode, x, key_hex }
POST /pa1/prg               { mode, seed_hex, output_bits }
POST /pa1/nist              { mode, seed_hex, n_bits }
POST /pa2/prf               { mode, key_hex, x, input_bits }
POST /pa2/prg_from_prf      { key_hex, seed_int, n_bytes }
POST /pa2/distinguishing_game { n_queries, input_bits }
GET  /health
GET  /
```

---

## Test Suite — 74 / 74 Passed

| File | Count | What's covered |
|------|-------|----------------|
| `test_pa1_owf.py` | 16 | DLP range/determinism/multiplicativity, AES-OWF, FIPS KAT vectors |
| `test_pa1_prg.py` | 17 | PRG_AES, PRG_DLP, OWF_from_PRG, make_prg factory |
| `test_pa1_nist.py` | 14 | Each test pass/fail cases, AES-PRG passes all 3 NIST tests |
| `test_pa2_prf.py` | 27 | Doubling PRG, PRF_GGM, PRF_AES, PRG_from_PRF, distinguishing game |

---

## Installation Record

```bash
python -m venv venv
venv/Scripts/pip install fastapi uvicorn pytest matplotlib numpy

cd frontend
npm create vite@latest . -- --template react
npm install
```

**requirements.txt:**
```
fastapi==0.135.2
uvicorn==0.42.0
pytest==9.0.2
matplotlib==3.10.8
numpy==2.4.4
```

---

## Important Notes

1. **PA2 depends on PA1** — `pa2/prf.py` imports `_aes128_encrypt_block` from `pa1/owf.py`.
2. **GL vector $r$** — randomly chosen at `PRG` construction. Pass `r` explicitly for cross-session reproducibility.
3. **DLP PRG is slow** — iterates 256-bit modular exponentiation per bit. Use `mode="aes"` for large outputs.
4. **NIST tests need $\geq 100$ bits** — returns `{'p_value': None, 'pass': False}` for shorter inputs.
5. **Runs test:** alternating $010101\cdots$ has $V_{\text{obs}} \approx n-1 \gg 2n\pi(1-\pi) \approx n/2$ — correctly fails. Not a bug.
6. **GGM domain size** = $2^{\texttt{input\_bits}}$ — default $2^8 = 256$ possible inputs.
7. **CORS is open** (`allow_origins=["*"]`) — development only.
