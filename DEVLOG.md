# CS8.401 — Principles of Information Security
## PA \#1 & PA \#2 — Development Log

**Date:** 2026-04-01  
**Project directory:** `c:\Users\lenovo\Downloads\pois project\`  
**Team stack:** React + Vite (frontend) · Python 3.14 + FastAPI + Uvicorn (backend) · pytest (testing) · matplotlib/numpy (analysis) · pip + venv (packages) · Git (version control)

---

## 1. Environment Discovery

Ran initial environment check:

```bash
python --version    # Python 3.14.0  ✓ (pre-installed)
node --version      # v24.11.1       ✓ (pre-installed)
npm --version       # 11.6.2         ✓ (pre-installed)
```

No base-tool installation needed — Python, Node, and npm were all already on the system.

---

## 2. Project Folder Structure Creation

```bash
mkdir -p "pois project/backend/pa1"
mkdir -p "pois project/backend/pa2"
mkdir -p "pois project/backend/api"
mkdir -p "pois project/frontend"
mkdir -p "pois project/docs"
mkdir -p "pois project/tests"
```

**Final directory layout:**

```
pois project/
├── backend/
│   ├── pa1/
│   │   ├── owf.py           ← One-Way Functions (DLP + AES)
│   │   ├── prg.py           ← PRG (HILL / Goldreich-Levin)
│   │   └── nist_tests.py    ← NIST SP 800-22 tests
│   ├── pa2/
│   │   └── prf.py           ← PRF (GGM Tree + AES plug-in)
│   └── api/
│       └── main.py          ← FastAPI REST bridge
├── frontend/                ← React + Vite UI
├── tests/                   ← 74 pytest tests
├── venv/                    ← Python virtual environment
├── requirements.txt
└── DEVLOG.md
```

---

## 3. Python Virtual Environment Setup

```bash
python -m venv venv
venv/Scripts/pip install fastapi uvicorn pytest matplotlib numpy
```

**Packages installed:**

| Package | Version | Purpose |
|---------|---------|---------|
| fastapi | 0.135.2 | REST API framework |
| uvicorn | 0.42.0 | ASGI server for FastAPI |
| pytest | 9.0.2 | Test runner |
| matplotlib | 3.10.8 | Plotting / visualization |
| numpy | 2.4.4 | Numerical operations |

---

## 4. React + Vite Frontend Scaffold

```bash
cd frontend
npm create vite@latest . -- --template react
npm install
```

151 packages installed, 0 vulnerabilities.

---

## 5. PA \#1 — One-Way Function (OWF)

**File:** `backend/pa1/owf.py`

### 5.1 DLP-based OWF

$$f(x) = g^x \bmod p$$

- $p$ is a 256-bit **safe prime** (Oakley Group 1, RFC 2409); $g = 2$ is a primitive root
- **Security basis:** Discrete Logarithm Problem — given $y = g^x \bmod p$, computing $x$ is computationally infeasible for large $p$
- Input: any non-negative integer $x$; Output: $g^x \bmod p \in [1,\, p-1]$
- Uses Python's built-in `pow(g, x, p)` (fast modular exponentiation)

**Multiplicative property** (used in tests):

$$g^{a+b} \bmod p \;=\; \bigl(g^a \bmod p\bigr) \cdot \bigl(g^b \bmod p\bigr) \bmod p$$

### 5.2 AES-based OWF

$$f(k) = \text{AES}_k\!\left(0^{128}\right) \oplus k$$

- **Security basis:** AES is a PRP; $\text{AES}_k(0^{128})$ is pseudorandom under unknown $k$, so $f(k)$ hides $k$
- AES-128 built **completely from scratch** — SubBytes, ShiftRows, MixColumns, AddRoundKey, KeyExpansion using only GF$(2^8)$ arithmetic
- Verified against **FIPS 197 Appendix B** and NIST known-answer test vectors:

$$\text{AES}_{0^{128}}\!\left(0^{128}\right) = \texttt{66e94bd4ef8a2c3b884cfa59ca342b2e}$$

> **Restriction respected:** Only `os.urandom` and built-in `int` operations used. No `hashlib`, `hmac`, `Crypto`, or any external library.

---

## 6. PA \#1 — Pseudorandom Generator (PRG)

**File:** `backend/pa1/prg.py`

### Construction: HILL / Goldreich-Levin Hard-Core Bit

Given OWF $f : \{0,1\}^n \to \{0,1\}^n$, define a PRG of stretch $\ell$ as:

$$G(x_0) \;=\; b(x_0) \;\|\; b(x_1) \;\|\; \cdots \;\|\; b(x_\ell)$$

where the state is iterated as:

$$x_{i+1} = f(x_i)$$

and $b(x_i)$ is the **Goldreich-Levin hard-core bit** with a fixed random projection vector $r$:

$$b(x_i) \;=\; \langle x_i,\, r \rangle \bmod 2 \;=\; \bigoplus_{j=1}^{n} \bigl(x_i^{(j)} \wedge r^{(j)}\bigr)$$

**Security:** By the Goldreich-Levin theorem, $b(x)$ is a hard-core bit for any OWF $f$, meaning no PPT adversary can predict $b(x)$ with probability $> \tfrac{1}{2} + \text{negl}(n)$ given $f(x)$. Chaining $\ell+1$ evaluations stretches $n$ bits to $n + \ell$ bits while maintaining pseudorandomness.

**Interface:**
```python
prg = PRG_AES(output_bits=256)
prg.seed(seed_bytes)       # 16-byte seed
bits = prg.next_bits(n)    # returns n pseudorandom bits as int
data = prg.generate_bytes(n)
```

### Bidirectional Reduction: PRG $\Rightarrow$ OWF

Given PRG $G : \{0,1\}^n \to \{0,1\}^{2n}$, define:

$$f_G(s) \;=\; G(s)\bigl[0 \;:\; n\bigr] \quad \text{(first } n \text{ bits of } G(s)\text{)}$$

**Security argument:** Suppose efficient inverter $\mathcal{A}$ breaks $f_G$. Build distinguisher $\mathcal{D}$ for $G$:

1. Given challenge $y$ (either $G(s)$ or uniform $U_{2n}$), extract $x = y[0:n]$
2. Run $\mathcal{A}(x)$ to recover candidate $s'$; compute $G(s')$
3. If $G(s') = y$, output "PRG"; else output "random"

If $\mathcal{A}$ inverts with non-negligible probability, $\mathcal{D}$ distinguishes with the same advantage — contradicting PRG security. $\square$

---

## 7. PA \#1 — NIST SP 800-22 Statistical Tests

**File:** `backend/pa1/nist_tests.py`

All three tests are implemented in pure Python (no scipy/statsmodels).

### Test 1: Frequency (Monobit) Test — NIST §2.1

Let $\epsilon = \epsilon_1 \epsilon_2 \cdots \epsilon_n$ be the bit sequence. Define:

$$S_n = \sum_{i=1}^{n} (2\epsilon_i - 1) \;=\; (\text{count of 1s}) - (\text{count of 0s})$$

Test statistic:

$$s_{\text{obs}} = \frac{|S_n|}{\sqrt{n}}$$

$$P\text{-value} = \operatorname{erfc}\!\left(\frac{s_{\text{obs}}}{\sqrt{2}}\right)$$

**Reject** (FAIL) if $P\text{-value} < 0.01$.

---

### Test 2: Runs Test — NIST §2.3

Pre-test: proportion of ones $\pi = \frac{\#\{i : \epsilon_i=1\}}{n}$.  
Reject pre-test if $|\pi - \tfrac{1}{2}| \geq \tau$ where $\tau = \dfrac{2}{\sqrt{n}}$.

Count the total number of runs $V_{\text{obs}}$ (a *run* is a maximal block of identical bits).

$$P\text{-value} = \operatorname{erfc}\!\left( \frac{\bigl|V_{\text{obs}} - 2n\pi(1-\pi)\bigr|}{2\sqrt{2n}\;\pi(1-\pi)} \right)$$

> **Note:** A perfectly alternating sequence $010101\cdots$ has $V_{\text{obs}} \approx n-1$, far exceeding the expected value $2n\pi(1-\pi) \approx \tfrac{n}{2}$, so it correctly **fails** this test.

---

### Test 3: Serial Test ($m=2$) — NIST §2.11

For a cyclic sequence, count occurrences of all $m$-bit patterns. Define:

$$\psi^2_m = \frac{2^m}{n} \sum_{\text{all } m\text{-bit patterns}} \bigl(\text{count}(\text{pattern})\bigr)^2 - n$$

Compute first and second differences:

$$\nabla\psi^2_m = \psi^2_m - \psi^2_{m-1}$$

$$\nabla^2\psi^2_m = \psi^2_m - 2\psi^2_{m-1} + \psi^2_{m-2}$$

$$P\text{-value}_1 = \Gamma\!\left(2^{m-2},\; \frac{\nabla\psi^2_m}{2}\right) \qquad P\text{-value}_2 = \Gamma\!\left(2^{m-3},\; \frac{\nabla^2\psi^2_m}{2}\right)$$

where $\Gamma(a, x)$ is the regularised upper incomplete gamma function, implemented via Lentz continued-fraction expansion.

---

## 8. PA \#2 — Pseudorandom Function (PRF) via GGM Tree

**File:** `backend/pa2/prf.py`

### Construction: GGM Tree

Given a **doubling PRG** $G : \{0,1\}^n \to \{0,1\}^{2n}$, split its output:

$$G_0(k) = G(k)\bigl[0:n\bigr], \qquad G_1(k) = G(k)\bigl[n:2n\bigr]$$

Define the PRF $F_k : \{0,1\}^\ell \to \{0,1\}^n$ for input $x = b_1 b_2 \cdots b_\ell$ as:

$$F_k(b_1 b_2 \cdots b_\ell) \;=\; G_{b_\ell}\!\Bigl(G_{b_{\ell-1}}\!\bigl(\cdots G_{b_1}(k) \cdots\bigr)\Bigr)$$

This is a traversal of a complete binary tree of depth $\ell$, following the path defined by the bits of $x$.

**Doubling PRG used in implementation:**

$$G_0(k) = \text{AES}_k(1), \qquad G_1(k) = \text{AES}_k(2)$$

**Security:** By a hybrid argument over the $2^\ell$ leaves, any PRF distinguisher for $F_k$ can be turned into a PRG distinguisher for $G$. Formally, if $\mathcal{A}$ distinguishes $F_k$ from a random function with advantage $\varepsilon$, there exists a PRG distinguisher with advantage $\varepsilon / 2^\ell$.

### AES Plug-in PRF

$$F_k(x) = \text{AES}_k(x)$$

Secure under the assumption that AES is a PRP. By the **PRP-PRF switching lemma**, a PRP is also a PRF with advantage loss at most $\binom{q}{2} / 2^n$ for $q$ queries.

### Bidirectional Reduction: PRF $\Rightarrow$ PRG

Given PRF $F_k : \{0,1\}^n \to \{0,1\}^n$, treating $s$ as an $(n-1)$-bit string:

$$G_k(s) \;=\; F_k(s \;\|\; 0) \;\|\; F_k(s \;\|\; 1)$$

This maps $n-1$ bits to $2n$ bits — a genuine expansion.

**Security:** Any distinguisher $\mathcal{D}$ for $G_k$ can be used to build a PRF adversary $\mathcal{A}$ with the same advantage: on queries from $\mathcal{D}$, $\mathcal{A}$ answers using two PRF queries per input, and forwards $\mathcal{D}$'s verdict.

### Minicrypt Clique (full chain)

$$\text{OWF} \;\Longleftrightarrow\; \text{PRG} \;\Longleftrightarrow\; \text{PRF} \;\Longleftrightarrow\; \text{PRP} \;\Longleftrightarrow\; \text{MAC}$$

| Reduction | Formula | File |
|-----------|---------|------|
| OWF $\to$ PRG | $G(x_0) = b(x_0) \| \cdots \| b(x_\ell)$ | `pa1/prg.py` |
| PRG $\to$ OWF | $f_G(s) = G(s)[0:n]$ | `pa1/prg.py` — `OWF_from_PRG` |
| PRG $\to$ PRF | $F_k(b_1\cdots b_\ell) = G_{b_\ell}(\cdots G_{b_1}(k)\cdots)$ | `pa2/prf.py` — `PRF_GGM` |
| PRF $\to$ PRG | $G_k(s) = F_k(s\|0) \| F_k(s\|1)$ | `pa2/prf.py` — `PRG_from_PRF` |
| PRP $\to$ PRF | $F_k(x) = \text{AES}_k(x)$ | `pa2/prf.py` — `PRF_AES` |

---

## 9. FastAPI REST Bridge

**File:** `backend/api/main.py`

| Endpoint | Method | Description |
|----------|--------|-------------|
| `GET /` | GET | Project info |
| `GET /health` | GET | Health check |
| `POST /pa1/owf` | POST | Compute OWF (DLP or AES) |
| `POST /pa1/prg` | POST | Generate pseudorandom bits |
| `POST /pa1/nist` | POST | Run NIST SP 800-22 tests |
| `POST /pa2/prf` | POST | Evaluate PRF (GGM or AES) |
| `POST /pa2/prg_from_prf` | POST | PRG from PRF reduction demo |
| `POST /pa2/distinguishing_game` | POST | PRF distinguishing game |

CORS enabled for all origins — allows Vite dev server (port 5173) to talk to FastAPI (port 8000).  
Interactive docs: **http://localhost:8000/docs**

---

## 10. React + Vite Frontend

**Files:** `frontend/src/App.jsx`, `frontend/src/App.css`, `frontend/src/api.js`

- **PA #1 tab:** OWF panel · PRG panel · NIST tests panel (p-value table + PASS/FAIL badges)
- **PA #2 tab:** PRF panel · PRG-from-PRF reduction demo · Distinguishing game panel
- Custom `useAsync` hook for loading/error/data state
- Dark theme with monospace output boxes

---

## 11. Test Results

```bash
venv/Scripts/python -m pytest tests/ -v
# 74 passed in 11.54s
```

| Test file | Tests | Result |
|-----------|-------|--------|
| test_pa1_owf.py | 16 | ✅ all pass |
| test_pa1_prg.py | 17 | ✅ all pass |
| test_pa1_nist.py | 14 | ✅ all pass |
| test_pa2_prf.py | 27 | ✅ all pass |

**Key verifications:**

- FIPS 197 Appendix B: $\text{AES}_k(pt) = \texttt{3925841d02dc09fbdc118597196a0b32}$ ✅
- NIST KAT: $\text{AES}_{0^{128}}(0^{128}) = \texttt{66e94bd4ef8a2c3b884cfa59ca342b2e}$ ✅
- AES-PRG output passes all 3 NIST SP 800-22 tests ✅
- GGM PRF is deterministic and collision-free over small domain ✅
- PRF distinguishing game: statistical distance $< 0.15$ ✅

---

## 12. How to Run

```bash
# Backend API
venv/Scripts/python -m uvicorn backend.api.main:app --reload --port 8000

# Frontend (separate terminal)
cd frontend && npm run dev

# Tests
venv/Scripts/python -m pytest tests/ -v
```

---

## 13. Key Design Decisions

| Decision | Rationale |
|----------|-----------|
| AES from scratch | Assignment prohibits external crypto libraries |
| GL hard-core bit for PRG | Goldreich-Levin theorem guarantees each output bit is unpredictable given $f(x)$ |
| CTR-mode doubling PRG for GGM | $\text{AES}_k(1)$ and $\text{AES}_k(2)$ give two independent pseudorandom halves |
| 256-bit safe prime for DLP-OWF | Large enough for DLP hardness; safe prime ensures strong generator subgroup |
| Gamma function from scratch | scipy not in required stack; Lentz continued fraction gives precision $< 10^{-12}$ |
