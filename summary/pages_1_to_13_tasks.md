# CS8.401: Principles of Information Security — Task Summary (Pages 1–13)

---

## Overview

This course (CS8.401) is a series of **21 Programming Assignments (PA#0 through PA#20)** that implement the entire cryptographic primitive hierarchy from scratch, culminating in a React web app that makes every reduction visual and interactive. The theoretical backbone is the **Minicrypt Equivalence Theorem**: OWF ⟺ PRG ⟺ PRF ⟺ OWP ⟺ PRP ⟺ MAC ⟺ CRHF ⟺ HMAC.

---

## Global Rules (Apply to ALL Assignments)

### The No-Library Rule (Critical)
- **No external cryptographic libraries** at any point (no PyCryptodome, OpenSSL, BouncyCastle, `cryptography`, `javax.crypto`, etc.)
- Every primitive must be your **own prior implementation** from the chain
- Permitted exceptions:
  - Standard library **arbitrary-precision integer arithmetic** (Python `int`, Java `BigInteger`)
  - **OS-level randomness** (`os.urandom`, `SecureRandom`)
- Specific dependency rules:
  - PA#18 (OT) needs PKC → must use your own PA#12 or PA#16 (not `import rsa`)
  - PA#6 / PA#10 (CCA-Enc) need MAC → must use your own PA#5 (PRF-MAC) or PA#10 (HMAC), not `hashlib`
  - PA#10 (HMAC) needs a hash → must use your own DLP Hash from PA#8, not SHA-256
  - PA#4 (Modes) needs a block cipher → must use your own PRF/PRP from PA#2 or your own AES
  - PA#20 (MPC) must use your own PA#19 and PA#18, not a garbled-circuit library

### Bidirectional Reductions Rule
- Every adjacent pair (A, B) in the clique must be implemented in **BOTH directions**:
  - **Forward**: construct B from A
  - **Backward**: show how breaking B would break A
- Full credit requires both directions. Forward-only earns partial credit.

---

## Cryptographic Primitive Hierarchy (Minicrypt Clique)

```
OWF ──(GGM)──► PRG ──(GGM)──► PRF ──► PRP
 │                                      │
 └──────────────────────────────────────┘
             OWP ◄──────────────┘
                    PRF ◄──────► MAC
                    CRHF ◄──────► HMAC ◄──► MAC
                    CPA-Enc ──► CCA-Enc
                    PKC ──► Digital Sig. / CCA-PKC
                    OT ──► Secure AND / Secure XOR ──► All 2-Party MPC
```

Two concrete foundations:
- **AES** — concrete PRP/PRF (based on GF(2⁸) algebraic structure)
- **DLP** — concrete OWF/OWP (`f(x) = gˣ mod p` in cyclic group G)

Security notion progression: `OTP → CPA-Secure → CCA1-Secure → CCA2-Secure`

---

## Part 0: The Minicrypt Clique Web Explorer (React Interactive App)

### What it is
A **React web application** that makes every reduction in the clique visual, interactive, and traceable with real data. It calls your PA implementations — does not reimplement them. Built **incrementally** alongside Parts I–IV.

### Core Problem the App Solves
Every abstract reduction says "given oracle for primitive A, construct B." The app forces you to trace how a **concrete function** (AES or DLP) flows all the way up the chain to B.

Two legs for every reduction:
- **Leg 1** (Column 1 — "Build"): Foundation → Source Primitive A (always under the hood)
- **Leg 2** (Column 2 — "Reduce"): Source Primitive A → Target Primitive B (visible on screen)

---

## PA #0 — Minicrypt Clique Web Explorer

### Layout to Implement

**Fixed three-tier layout:**

1. **Top bar — Foundation selector**
   - Toggle with two options: `AES-128 (PRP)` and `DLP (gˣ mod p)`
   - Changing toggle affects Column 1 entirely and re-runs all computations

2. **Two-column main area:**
   - **Column 1 — "Build" panel** (Leg 1: Foundation → Source Primitive A):
     - Dropdown: select source primitive A (OWF, PRG, PRF, PRP, MAC, CRHF, HMAC)
     - Input field: raw key or seed (hex string)
     - Step-through display: shows each sub-reduction from foundation to A with actual intermediate byte values at each step
     - Example for AES + PRG: `[AES key] --PRF--> [Fk(0)||Fk(1)] = [PRG output]`
   - **Column 2 — "Reduce" panel** (Leg 2: Source Primitive A → Target Primitive B):
     - Dropdown: select target primitive B (must differ from A)
     - Input field: message or query to evaluate
     - Step-through display: shows reduction from A to B with real intermediate values
     - Output of Column 1 is automatically piped as the concrete implementation of A used in Column 2
3. **Bottom panel — Reduction proof summary:**
   - Collapsible box showing full chain: Foundation → A → B
   - Theorem names (HILL, GGM, Luby-Rackoff, etc.) at each step
   - Security claim at each step

### Architectural Rule (Critical)
- Column 2 **must NOT** call foundation (AES or DLP) directly
- Column 2 may only call source primitive A that Column 1 has constructed
- Each primitive is a black box to the layer above it

### Routing Table to Implement

| Source A | Target B | Reduction chain used |
|----------|----------|----------------------|
| OWF | PRG | HILL hard-core-bit construction |
| OWF | OWP | DLP is already an OWP (identity for DLP foundation) |
| PRG | PRF | GGM tree |
| PRF | PRP | Luby-Rackoff 3-round Feistel |
| PRF | MAC | Macₖ(m) = Fₖ(m) |
| PRP | MAC | PRP/PRF switching lemma, then MAC |
| CRHF | HMAC | HMAC construction (PA#10) |
| HMAC | MAC | Direct (HMAC is a MAC) |
| Any | Any | Compose the above steps as needed |

Also support **backward reductions** (B → A) via bidirectional mode toggle.

### Required Features (9 items)

1. **React app scaffold** — Create React App or Vite, three-tier layout, clearly two-column
2. **Foundation layer** — Implement two foundation modules:
   - `AESFoundation`: wraps PA#2 AES-based PRF. Exposes `asOWF()`, `asPRF()`, `asPRP()`
   - `DLPFoundation`: wraps PA#1 DLP-based OWF. Exposes `asOWF()`, `asOWP()`
   - Both share a common `Foundation` interface so the rest of the app is agnostic
3. **Column 1 — Build panel**: Given foundation and target source primitive A, compute and display full chain Foundation → A showing each intermediate value. Must call existing PA implementations (compiled to WebAssembly or via local API — **not** reimplemented in JavaScript). Each step displays: function applied, input bytes (hex), output bytes (hex).
4. **Column 2 — Reduce panel**: Given concrete instance of A from Column 1 and target primitive B, compute and display reduction A → B step by step. Column 2 receives A as a black box (function object) and must not inspect its internals.
5. **Routing table**: Implement `reduce(A, B, foundation)` returning ordered list of reduction steps. Handle all pairs in table. For unsupported pairs (e.g., CRHF → OWP), display clear message explaining why no direct path exists and suggest using the bidirectional toggle.
6. **Live data flow**: When user changes any input (foundation toggle, source/target primitive, key, message), all panels update in **real time without page reload**.
7. **Bidirectional mode**: Toggle "Forward (A → B) / Backward (B → A)" that swaps columns and shows reverse reduction (e.g., MAC → PRF by querying MAC as PRF oracle and running distinguishing game).
8. **Proof summary panel**: For each selected pair (A, B), display formal security chain — which theorem justifies each step, what the security reduction is ("if adversary breaks B with advantage ε, it breaks A with advantage ε' ≥ ε/q"), and the PA number that implements each step.
9. **Stub support**: Primitives not yet implemented show "Not implemented yet (due: PA#N)" placeholder with greyed-out step. App must be fully runnable with any subset of primitives implemented.

### PA #0 Demo Deliverable (Grader Checks)
- Foundation toggle (AES / DLP) is visible and switches without errors
- Both columns render with their dropdowns and input fields
- Selecting any primitive pair shows "Not yet implemented" placeholder with correct PA number — not a blank or crash
- Bottom proof panel opens/closes on click and displays static reduction chain text for the selected pair
- **Toy parameters**: No real crypto needed for PA#0. Stub functions returning fixed hex strings are fine at this stage.

---

## Required Bidirectional Implementations Summary

### OWF ⟺ PRG
- **Forward** OWF → PRG: HILL/iterative construction — apply f repeatedly with hard-core predicate b; output `b(f⁰(x)) || b(f¹(x)) || ...`
- **Backward** PRG → OWF: Any PRG G is immediately a OWF. Define `f(s) = G(s)`; inversion of f would invert G, recovering the seed and breaking pseudorandomness.

### OWF ⟺ OWP
- **Forward** OWF → OWP: Any OWF on domain with efficiently samplable pre-images can be converted to OWP (e.g., DLP: `f(x) = gˣ mod p` is OWP on ℤq)
- **Backward** OWP → OWF: Immediate — OWP is a special case of OWF (bijective, hence also hard to invert)

### PRG ⟺ PRF
- **Forward** PRG → PRF: GGM tree construction. Given `G: {0,1}ⁿ → {0,1}²ⁿ`, define `Fk(b₁...bₙ) = G_{b_n}(...G_{b₁}(k))`
- **Backward** PRF → PRG: Define `G(s) = Fs(0) || Fs(1)`. If G were distinguishable from random, the distinguisher breaks PRF security.

### OWP ⟺ PRG
- **Forward** OWP → PRG: Any OWP with hard-core predicate b yields PRG: `G(x) = (f(x), b(x))`, expanding by one bit per application
- **Backward** PRG → OWP: A length-preserving PRG is itself an OWP (injective and hard to invert, hence permutation on its range)

### PRF ⟺ PRP
- **Forward** PRF → PRP: **Luby-Rackoff construction** — apply three or four rounds of Feistel network using PRF as round function. 3-round Feistel → secure PRP; 4-round Feistel → secure *strong* PRP.
- **Backward** PRP → PRF: A PRP over super-polynomially large domain is computationally indistinguishable from PRF (PRF/PRP switching lemma). Concretely, AES (PRP) used directly as PRF in CTR, OFB, GCM.

### PRF ⟺ MAC
- **Forward** PRF → MAC: `Macₖ(m) = Fₖ(m)`. If MAC were forgeable, forger distinguishes Fₖ from random, breaking PRF security.
- **Backward** MAC → PRF: A secure EUF-CMA MAC on uniformly random messages is a PRF. Use MAC oracle as PRF oracle; unforgeability implies pseudorandomness of outputs.

### PRP ⟺ MAC (via PRF as bridge)
- **Forward** PRP → MAC: Use PRP directly as PRF (switching lemma), then apply PRF → MAC. Concretely: AES-CMAC and CBC-MAC use block cipher (PRP) as underlying primitive.
- **Backward** MAC → PRP: Via MAC → PRF (above) then PRF → PRP (Luby-Rackoff).

### OWP ⟺ PRF (completing the clique)
- **Forward** OWP → PRF: OWP → PRG (above) then PRG → PRF (GGM)
- **Backward** PRF → OWP: PRF → PRP (Luby-Rackoff); PRP on {0,1}ⁿ keyed by k gives OWP `f(k) = PRPₖ(0ⁿ)`

### CRHF ⟺ HMAC
- **Forward** CRHF → HMAC: Given hash function H built on PRF-secure compression function (e.g., PA#8 DLP hash), define `HMACₖ(m) = H((k ⊕ opad) || H((k ⊕ ipad) || m))`. Security holds because inner hash acts as PRF on message, outer hash acts as PRF on inner hash output.
- **Backward** HMAC → CRHF: Fix a key k and define `H'(m) = HMACₖ(m)`. This keyed function is collision-resistant (any collision would constitute MAC forgery). More generally, use HMAC compression step as compression function in new Merkle-Damgård hash.

### HMAC ⟺ MAC
- **Forward** HMAC → MAC: HMAC is a secure EUF-CMA MAC when compression function is a PRF. This is exactly what PA#10 implements.
- **Backward** MAC → HMAC: Any secure PRF-based MAC can be cast in the HMAC double-hash structure by treating the MAC as inner compression step.

### CRHF ⟺ MAC (full bridge via HMAC)
- **Forward** CRHF → MAC: CRHF → HMAC → MAC (two steps above). Concretely: PA#8 DLP hash → PA#10 HMAC → PA#10 CCA-secure encryption.
- **Backward** MAC → CRHF: A secure MAC serves as collision-resistant compression function (any collision in MAC output is a forgery). Apply Merkle-Damgård transform (PA#7) to get a full CRHF.

---

## Complete Assignment List (All 21 PAs)

### Part I — Symmetric Cryptography (PA#1–PA#6)
| PA | Topic |
|----|-------|
| PA#1 | One-Way Functions & Pseudorandom Generators |
| PA#2 | Pseudorandom Functions via GGM Tree |
| PA#3 | CPA-Secure Symmetric Encryption |
| PA#4 | Modes of Operation |
| PA#5 | Message Authentication Codes (MACs) |
| PA#6 | CCA-Secure Symmetric Encryption |

### Part II — Hashing and Data Integrity (PA#7–PA#10)
| PA | Topic |
|----|-------|
| PA#7 | Merkle-Damgård Transform |
| PA#8 | DLP-Based Collision-Resistant Hash Function |
| PA#9 | Birthday Attack (Collision Finding) |
| PA#10 | HMAC and HMAC-Based CCA-Secure Encryption |

### Part III — Public-Key Cryptography / Cryptomania (PA#11–PA#17)
| PA | Topic |
|----|-------|
| PA#11 | Diffie-Hellman Key Exchange (SKE) |
| PA#12 | Textbook RSA |
| PA#13 | Miller-Rabin Primality Testing |
| PA#14 | Chinese Remainder Theorem & Breaking Textbook RSA |
| PA#15 | Digital Signatures |
| PA#16 | ElGamal Public-Key Cryptosystem |
| PA#17 | CCA-Secure PKC |

### Part IV — Secure Multi-Party Computation (PA#18–PA#20)
| PA | Topic |
|----|-------|
| PA#18 | Oblivious Transfer (OT) |
| PA#19 | Secure AND Gate |
| PA#20 | All 2-Party Secure Computation (Yao / GMW) |

---

## Current Status (as of PA3)

Based on existing project state:
- **PA#1 and PA#2** — Fully implemented, 74 tests passing
- **PA#3** — In progress (file `prp.py` is currently open)
- **PA#0** (React web app) — To be built incrementally as PAs are completed

---

## Key Architectural Decisions to Keep in Mind

1. Each PA builds on the previous — breaking the dependency chain invalidates the implementation
2. The React app must call PA implementations via **WebAssembly or local API** — not re-implement in JS
3. Column 2 in the React app must treat Column 1's output as a **black box** — no peeking inside
4. For unsupported reduction pairs in the routing table, show a clear message and suggest bidirectional toggle
5. Stub out unimplemented PAs with `"Not implemented yet (due: PA#N)"` — the app must remain runnable at all times
