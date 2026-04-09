import { useState, useEffect, useRef } from "react";
import { api } from "./api";
import { getFoundation } from "./foundations";
import { Math, Spinner, SegControl } from "./shared";
import {
  planRoute,
  getValidTargets,
  getEffectiveReductionKey,
  isRouteSupported,
  describeRoute,
} from "./routePlanner";

// ─── Helpers ──────────────────────────────────────────────────────────────────
function normalizeHex(h) {
  return (h ?? "").replace(/^0x/i, "").toLowerCase();
}
function truncHex(h, chars = 32) {
  const s = normalizeHex(h);
  return s.length > chars ? s.slice(0, chars) + "…" : s;
}
function bitsPreview(hexStr, maxBits = 64) {
  const h = normalizeHex(hexStr);
  const bits = h.split("").flatMap(c =>
    parseInt(c, 16).toString(2).padStart(4, "0").split("")
  ).slice(0, maxBits).join("");
  return bits;
}

// ─── Primitive labels ──────────────────────────────────────────────────────────
const PRIM_LABELS = {
  owf:  "OWF",
  prg:  "PRG",
  prf:  "PRF",
  prp:  "PRP",
  mac:  "MAC",
  owp:  "OWP",
  crhf: "CRHF",
  hmac: "HMAC",
};

// ─── Reduction metadata ───────────────────────────────────────────────────────
const REDUCTIONS = {
  "owf:prg": {
    labelA: "OWF", labelB: "PRG",
    theorem: "\\text{OWF} \\Rightarrow \\text{PRG}",
    theoremName: "HILL Theorem (Goldreich–Levin, 1989)",
    formula: "G(s) = b(s) \\| b(f(s)) \\| b(f^2(s)) \\| \\cdots",
    proofSketch: "Define hard-core bit b(xᵢ) = ⟨xᵢ, r⟩ mod 2. By Goldreich–Levin, b(xᵢ) is unpredictable given f(xᵢ). Applying f iteratively and extracting one bit per step yields a PRG that stretches any OWF.",
    securityClaim: "If adversary breaks PRG with advantage ε, it inverts OWF on fraction ε/n of inputs.",
    blackBoxNote: "PRG only calls f(·) as a black box — never inspects AES or DLP internals.",
    paNum: 1, paLink: "pa1", live: true,
  },
  "prg:prf": {
    labelA: "PRG", labelB: "PRF",
    theorem: "\\text{PRG} \\Rightarrow \\text{PRF}",
    theoremName: "GGM Construction (Goldreich–Goldwasser–Micali, 1986)",
    formula: "F_k(b_1\\cdots b_\\ell) = G_{b_\\ell}(\\cdots G_{b_1}(k)\\cdots)",
    proofSketch: "Build a binary tree of depth ℓ. Each internal node applies the PRG to double key material. A hybrid argument shows swapping each level introduces only negligible advantage.",
    securityClaim: "If adversary breaks PRF with advantage ε, it distinguishes PRG with advantage ε/ℓ.",
    blackBoxNote: "GGM calls G(·) at each tree node — never sees the OWF or AES layer directly.",
    paNum: 2, paLink: "pa2", live: true,
  },
  "prf:prg": {
    labelA: "PRF", labelB: "PRG",
    theorem: "\\text{PRF} \\Rightarrow \\text{PRG}",
    theoremName: "PRF → PRG Reduction",
    formula: "G_k(s) = F_k(s\\,\\|\\,0)\\,\\|\\,F_k(s\\,\\|\\,1)",
    proofSketch: "Any distinguisher D for G_k converts directly to a PRF adversary A with identical advantage: A simulates D by querying its PRF oracle for F_k(s‖0) and F_k(s‖1).",
    securityClaim: "If adversary distinguishes PRG with advantage ε, it breaks PRF with advantage ε.",
    blackBoxNote: "PRG calls F_k(·) with concatenated inputs — treats PRF as an opaque oracle.",
    paNum: 2, paLink: "pa2", live: true,
  },
  "owf:owp": {
    labelA: "OWF", labelB: "OWP",
    theorem: "\\text{OWF} \\Rightarrow \\text{OWP}",
    theoremName: "OWF → OWP via DLP",
    formula: "f(x) = g^x \\bmod p \\text{ is a OWP on } \\mathbb{Z}_q",
    proofSketch: "Any OWF on a domain with efficiently samplable pre-images can be converted to a OWP. DLP: f(x) = gˣ mod p is bijective on ℤq and hard to invert.",
    securityClaim: "If adversary inverts OWP with probability ε, it inverts OWF with probability ε.",
    blackBoxNote: "Uses DLP foundation directly as an OWP.",
    paNum: 1, paLink: "pa1", live: false,
  },
  "owp:prg": {
    labelA: "OWP", labelB: "PRG",
    theorem: "\\text{OWP} \\Rightarrow \\text{PRG}",
    theoremName: "OWP + Hard-Core Bit → PRG",
    formula: "G(x) = (f(x),\\; b(x))",
    proofSketch: "Any OWP with hard-core predicate b yields a PRG that expands by one bit per application: G(x) = (f(x), b(x)).",
    securityClaim: "If adversary distinguishes PRG with advantage ε, it predicts hard-core bit with advantage ε.",
    blackBoxNote: "PRG treats OWP as a black-box permutation.",
    paNum: 1, paLink: "pa1", live: false,
  },
  "owp:prf": {
    labelA: "OWP", labelB: "PRF",
    theorem: "\\text{OWP} \\Rightarrow \\text{PRF}",
    theoremName: "OWP → PRG → PRF (two hops)",
    formula: "\\text{OWP} \\xrightarrow{\\text{HC bit}} \\text{PRG} \\xrightarrow{\\text{GGM}} \\text{PRF}",
    proofSketch: "Compose: OWP → PRG (via hard-core bit) then PRG → PRF (via GGM tree). Each step introduces only negligible additional advantage.",
    securityClaim: "If adversary breaks PRF with advantage ε, it inverts OWP with advantage ε/ℓ².",
    blackBoxNote: "Two-hop reduction composed automatically by the routing table.",
    paNum: 2, paLink: "pa2", live: false,
  },
  "prf:prp": {
    labelA: "PRF", labelB: "PRP",
    theorem: "\\text{PRF} \\Rightarrow \\text{PRP}",
    theoremName: "Luby–Rackoff Construction (1988)",
    formula: "\\text{Feistel}_3: L_{i+1} = R_i,\\; R_{i+1} = L_i \\oplus F_k(R_i)",
    proofSketch: "Apply three rounds of Feistel network using PRF as round function. A 3-round Feistel yields a secure PRP; 4-round yields a strong PRP.",
    securityClaim: "If adversary breaks PRP with advantage ε making q queries, it breaks PRF with advantage ε - q²/2ⁿ.",
    blackBoxNote: "Luby–Rackoff Feistel only calls F_k(·) as round function — never inspects the PRF internals.",
    paNum: 3, paLink: "pa3", live: false,
  },
  "prf:mac": {
    labelA: "PRF", labelB: "MAC",
    theorem: "\\text{PRF} \\Rightarrow \\text{MAC}",
    theoremName: "PRF-MAC Construction",
    formula: "\\text{Mac}_k(m) = F_k(m)",
    proofSketch: "Define Mac_k(m) = F_k(m). If the MAC were EUF-CMA forgeable, the forger distinguishes F_k from a random function, breaking PRF security.",
    securityClaim: "If adversary forges MAC with advantage ε after q queries, it breaks PRF with advantage ε - q/2ⁿ.",
    blackBoxNote: "MAC calls F_k(·) as a black-box PRF oracle.",
    paNum: 4, paLink: "pa4", live: false,
  },
  "prp:mac": {
    labelA: "PRP", labelB: "MAC",
    theorem: "\\text{PRP} \\Rightarrow \\text{MAC}",
    theoremName: "PRP/PRF Switching Lemma + PRF-MAC",
    formula: "\\text{PRP} \\xrightarrow{\\text{switch}} \\text{PRF} \\xrightarrow{\\text{MAC}} \\text{MAC}",
    proofSketch: "By the PRP/PRF switching lemma, a PRP over a super-polynomially large domain is computationally indistinguishable from a PRF. Then apply PRF-MAC.",
    securityClaim: "If adversary forges MAC with advantage ε, it breaks PRP with advantage ε - q²/2ⁿ.",
    blackBoxNote: "Uses PRP (block cipher) as PRF via switching lemma, then applies PRF-MAC.",
    paNum: 4, paLink: "pa4", live: false,
  },
  "crhf:hmac": {
    labelA: "CRHF", labelB: "HMAC",
    theorem: "\\text{CRHF} \\Rightarrow \\text{HMAC}",
    theoremName: "HMAC Construction (PA#10)",
    formula: "\\text{HMAC}_k(m) = H\\!\\left((k\\oplus\\text{opad})\\,\\|\\,H((k\\oplus\\text{ipad})\\,\\|\\,m)\\right)",
    proofSketch: "Given H built on a PRF-secure compression function (PA#8 DLP hash), define HMAC as above. The inner hash acts as PRF on message; outer hash acts as PRF on inner output.",
    securityClaim: "If adversary forges HMAC with advantage ε, it either finds collision in CRHF or breaks PRF of compression function with advantage ≥ ε/2.",
    blackBoxNote: "HMAC treats hash H as a black-box collision-resistant function.",
    paNum: 4, paLink: "pa4", live: false,
  },
  "hmac:mac": {
    labelA: "HMAC", labelB: "MAC",
    theorem: "\\text{HMAC} \\Rightarrow \\text{MAC}",
    theoremName: "HMAC is a secure EUF-CMA MAC",
    formula: "\\text{HMAC}_k(m) \\text{ is EUF-CMA secure when compression function is PRF}",
    proofSketch: "HMAC is a secure EUF-CMA MAC when the compression function is a PRF. Security follows directly from the PRF security of the compression step.",
    securityClaim: "If adversary forges MAC (=HMAC) with advantage ε, it breaks PRF of compression function with advantage ε.",
    blackBoxNote: "HMAC is already a MAC — this is a direct security claim, not a new construction.",
    paNum: 4, paLink: "pa4", live: false,
  },
  "prg:owf_back": {
    labelA: "PRG", labelB: "OWF",
    theorem: "\\text{PRG} \\Rightarrow \\text{OWF}",
    theoremName: "PRG is immediately a OWF (backward)",
    formula: "f(s) = G(s)",
    proofSketch: "Any PRG G is immediately a OWF: define f(s) = G(s). Inversion of f would recover the seed and break pseudorandomness of G.",
    securityClaim: "If adversary inverts OWF f=G with probability ε, it distinguishes PRG with advantage ε.",
    blackBoxNote: "OWF uses PRG oracle, treating it as a black box.",
    paNum: 1, paLink: "pa1", live: false,
  },
  "owp:owf_back": {
    labelA: "OWP", labelB: "OWF",
    theorem: "\\text{OWP} \\Rightarrow \\text{OWF}",
    theoremName: "OWP is a special case of OWF (backward)",
    formula: "\\text{OWP} \\subset \\text{OWF} \\text{ (bijective, hence also hard to invert)}",
    proofSketch: "An OWP is a bijective OWF. Any adversary inverting the OWF would immediately invert the OWP as well.",
    securityClaim: "If adversary inverts OWF with probability ε, it inverts OWP with probability ε.",
    blackBoxNote: "OWF uses OWP as a special-case black box.",
    paNum: 1, paLink: "pa1", live: false,
  },
  "prp:prf_back": {
    labelA: "PRP", labelB: "PRF",
    theorem: "\\text{PRP} \\Rightarrow \\text{PRF}",
    theoremName: "PRP/PRF Switching Lemma (backward)",
    formula: "\\Pr[D^{P_k}=1] - \\Pr[D^{f}=1] \\leq \\frac{q^2}{2^n}",
    proofSketch: "A PRP over a super-polynomially large domain is computationally indistinguishable from a PRF (PRP/PRF switching lemma). Concretely, AES (PRP) is used directly as PRF in CTR, OFB, GCM.",
    securityClaim: "If adversary distinguishes PRF with advantage ε, it distinguishes PRP with advantage ε - q²/2ⁿ.",
    blackBoxNote: "Adversary uses PRP as PRF oracle via switching lemma.",
    paNum: 3, paLink: "pa3", live: false,
  },
  "mac:prf_back": {
    labelA: "MAC", labelB: "PRF",
    theorem: "\\text{MAC} \\Rightarrow \\text{PRF}",
    theoremName: "EUF-CMA MAC on uniform messages is PRF (backward)",
    formula: "\\text{Use MAC oracle as PRF oracle — unforgeability} \\Rightarrow \\text{pseudorandomness}",
    proofSketch: "A secure EUF-CMA MAC on uniformly random messages is a PRF. Use the MAC oracle as a PRF oracle; unforgeability implies pseudorandomness of outputs.",
    securityClaim: "If adversary breaks PRF with advantage ε, it forges MAC with advantage ε.",
    blackBoxNote: "PRF adversary calls MAC oracle as black-box PRF.",
    paNum: 4, paLink: "pa4", live: false,
  },
  "hmac:crhf_back": {
    labelA: "HMAC", labelB: "CRHF",
    theorem: "\\text{HMAC} \\Rightarrow \\text{CRHF}",
    theoremName: "HMAC → CRHF (fix key, backward)",
    formula: "H'(m) = \\text{HMAC}_k(m) \\text{ is collision-resistant}",
    proofSketch: "Fix a key k and define H'(m) = HMAC_k(m). This keyed function is collision-resistant (any collision would constitute a MAC forgery).",
    securityClaim: "If adversary finds collision in CRHF H', it forges HMAC with probability 1.",
    blackBoxNote: "CRHF construction wraps HMAC as a black-box keyed function.",
    paNum: 4, paLink: "pa4", live: false,
  },
  "mac:hmac_back": {
    labelA: "MAC", labelB: "HMAC",
    theorem: "\\text{MAC} \\Rightarrow \\text{HMAC}",
    theoremName: "MAC → HMAC double-hash structure (backward)",
    formula: "\\text{Any PRF-based MAC} \\Rightarrow \\text{cast as HMAC compression step}",
    proofSketch: "Any secure PRF-based MAC can be cast in the HMAC double-hash structure by treating the MAC as the inner compression step.",
    securityClaim: "If adversary forges HMAC with advantage ε, it forges underlying MAC with advantage ε.",
    blackBoxNote: "HMAC treats MAC oracle as inner compression black box.",
    paNum: 4, paLink: "pa4", live: false,
  },
};

// ─── Unsupported pair explanations ────────────────────────────────────────────
const UNSUPPORTED_PAIRS = {
  "crhf:owf":  "No direct path from CRHF → OWF in the forward direction.",
  "crhf:prg":  "No direct one-step path CRHF → PRG.",
  "crhf:prf":  "No direct path CRHF → PRF.",
  "crhf:prp":  "No direct path CRHF → PRP.",
  "crhf:owp":  "No direct path CRHF → OWP in the forward direction.",
  "crhf:mac":  "No direct one-step path CRHF → MAC.",
  "mac:prg":   "No direct path MAC → PRG.",
  "mac:owf":   "No direct path MAC → OWF.",
  "mac:owp":   "No direct path MAC → OWP in forward direction.",
  "hmac:owf":  "No direct path.",
  "hmac:prg":  "No direct path HMAC → PRG.",
  "hmac:prf":  "No direct path HMAC → PRF.",
  "hmac:prp":  "No direct path HMAC → PRP.",
  "hmac:owp":  "No direct path HMAC → OWP.",
  "hmac:crhf": "No direct forward path HMAC → CRHF.",
  "prp:prg":   "No direct path PRP → PRG in forward direction.",
  "prp:prf":   "No direct forward path PRP → PRF.",
  "prp:owf":   "No direct path PRP → OWF in forward direction.",
  "prp:owp":   "No direct path PRP → OWP.",
  "prp:crhf":  "No direct path PRP → CRHF.",
  "prp:hmac":  "No direct path PRP → HMAC.",
  "prf:owf":   "PRF → OWF is not a standard forward reduction.",
  "prf:owp":   "PRF → OWP: multi-hop via Luby–Rackoff.",
  "prf:crhf":  "PRF → CRHF: Use MAC→CRHF as backward reduction.",
  "prf:hmac":  "PRF → HMAC is multi-hop.",
  "prg:owf":   "PRG → OWF: Backward reduction.",
  "prg:prp":   "PRG → PRP: Multi-hop via PRG → PRF → PRP.",
  "prg:mac":   "PRG → MAC: Multi-hop via PRG → PRF → MAC.",
  "prg:owp":   "PRG → OWP: Multi-hop.",
  "prg:crhf":  "PRG → CRHF: Not a direct forward reduction.",
  "prg:hmac":  "PRG → HMAC: Multi-hop.",
  "owf:prf":   "OWF → PRF: Multi-hop via OWF → PRG → PRF.",
  "owf:prp":   "OWF → PRP: Multi-hop via OWF → PRG → PRF → PRP.",
  "owf:mac":   "OWF → MAC: Multi-hop.",
  "owf:crhf":  "OWF → CRHF: Multi-hop.",
  "owf:hmac":  "OWF → HMAC: Multi-hop.",
  "owp:mac":   "OWP → MAC: Multi-hop.",
  "owp:crhf":  "OWP → CRHF: Multi-hop.",
  "owp:hmac":  "OWP → HMAC: Multi-hop.",
  "owp:prp":   "OWP → PRP: Multi-hop.",
};

// ─── Source options ────────────────────────────────────────────────────────────
const SOURCE_OPTIONS = [
  { value: "owf",  label: "OWF — One-Way Function" },
  { value: "prg",  label: "PRG — Pseudorandom Generator" },
  { value: "prf",  label: "PRF — Pseudorandom Function" },
  { value: "prp",  label: "PRP — Pseudorandom Permutation" },
  { value: "mac",  label: "MAC — Message Authentication Code" },
  { value: "owp",  label: "OWP — One-Way Permutation" },
  { value: "crhf", label: "CRHF — Collision-Resistant Hash" },
  { value: "hmac", label: "HMAC — Hash-Based MAC" },
];

// ─── Step trace component ─────────────────────────────────────────────────────
function StepTrace({ steps }) {
  return (
    <div className="step-trace">
      {steps.map((s, i) => (
        <div key={i} className="step-row">
          <div className="step-num">{i + 1}</div>
          <div className="step-body">
            <div className="step-label">{s.label}</div>
            {s.formula && <div className="step-formula"><Math expr={s.formula} /></div>}
            {s.value   && <div className="step-value mono">{s.value}</div>}
            {s.note    && <div className="step-note">{s.note}</div>}
          </div>
        </div>
      ))}
    </div>
  );
}

// ─── Build Col1 steps ─────────────────────────────────────────────────────────
function buildCol1Steps(source, foundation, col1Data, userKey) {
  if (!col1Data) return [];
  const isAes = foundation === "aes";
  const foundationStep = {
    label: `Leg 1 — Foundation: ${isAes ? "AES-128 (PRP/PRF)" : "DLP (gˣ mod p)"}`,
    formula: isAes
      ? "\\text{Foundation:}\\;\\text{AES}_{128} \\xrightarrow{\\text{PRP/PRF switch}} \\text{PRF}"
      : "\\text{Foundation:}\\;f(x) = g^x \\bmod p \\;\\text{(OWF/OWP)}",
    value: truncHex(userKey ?? "", 24),
    note: isAes
      ? "AES key input — AES acts as both PRP and PRF (via switching lemma)"
      : "DLP group: g=2, 768-bit safe prime p — bijection on ℤq",
  };
  if (source === "owf") {
    const isDlp = col1Data.mode === "dlp";
    return [
      foundationStep,
      {
        label: isDlp ? "DLP → OWF: apply f(x) = gˣ mod p" : "AES → OWF: apply f(k) = AES_k(0¹²⁸) ⊕ k",
        formula: isDlp ? "f(x) = g^{x} \\bmod p" : "f(k) = \\text{AES}_k(\\mathbf{0})\\oplus k",
        value: truncHex(col1Data.output_hex, 40),
        note: `${col1Data.output_bits ?? 128} bits output`,
      },
      {
        label: "OWF output → piped to Column 2 as black-box seed",
        value: truncHex(col1Data.output_hex, 32),
        note: "Column 2 receives this as a black box — never inspects the foundation",
      },
    ];
  }
  if (source === "prg") {
    return [
      foundationStep,
      {
        label: isAes ? "AES (PRF) → PRG: G(s) = F_k(0) ‖ F_k(1)" : "DLP (OWF) → PRG: GL hard-core bit construction",
        formula: isAes ? "G(s) = F_k(0)\\,\\|\\,F_k(1)" : "G(s) = b(s)\\,\\|\\,b(f(s))\\,\\|\\,\\cdots",
        note: isAes ? "PRF → PRG reduction applied to AES foundation" : "HILL/Goldreich–Levin hard-core predicate applied to DLP",
      },
      {
        label: "PRG output → piped to Column 2",
        value: bitsPreview(col1Data.output_hex, 48) + "…",
        note: `${col1Data.output_bits} bits | Bit balance: ${((col1Data.statistics?.ones_ratio ?? 0.5) * 100).toFixed(1)}% ones`,
      },
    ];
  }
  if (source === "prf") {
    return [
      foundationStep,
      {
        label: isAes ? "AES (PRP) → PRF: GGM tree construction" : "DLP → OWF → PRG → PRF: multi-hop chain",
        formula: isAes
          ? "F_k(b_1\\cdots b_\\ell) = G_{b_\\ell}(\\cdots G_{b_1}(k)\\cdots)"
          : "\\text{DLP} \\xrightarrow{\\text{HC}} \\text{PRG} \\xrightarrow{\\text{GGM}} \\text{PRF}",
        note: isAes
          ? "GGM tree uses AES as base PRF seed"
          : "Full multi-hop: DLP hardness → OWF → PRG (GL) → PRF (GGM)",
      },
      {
        label: "PRF output → piped to Column 2",
        value: truncHex(col1Data.output_hex, 32),
        note: "128-bit pseudorandom output — Column 2 uses this as its PRF key",
      },
    ];
  }
  return [];
}

// ─── Build Col2 steps ─────────────────────────────────────────────────────────
function buildCol2Steps(reductionKey, col1Data, col2Data) {
  if (!col2Data) return [];
  if (reductionKey === "owf:prg") {
    const seed = normalizeHex(col1Data?.output_hex ?? "").slice(0, 32).padEnd(32, "0");
    return [
      {
        label: "Black-box input: OWF output as seed",
        formula: "s = f(x_{\\text{prev}})[:128\\text{ bits}]",
        value: seed,
        note: "PRG never inspects how f was computed",
      },
      {
        label: "Extract Goldreich-Levin hard-core bits",
        formula: "b_i = \\langle x_i, r\\rangle \\bmod 2,\\quad x_{i+1} = f(x_i)",
        note: `Generating ${col2Data.output_bits} bits`,
      },
      {
        label: "PRG output (pseudorandom bitstring)",
        value: bitsPreview(col2Data.output_hex, 64) + "…",
        note: `Ones ratio: ${((col2Data.statistics?.ones_ratio ?? 0.5) * 100).toFixed(1)}%  |  Entropy ≈ uniform`,
      },
    ];
  }
  if (reductionKey === "prg:prf") {
    const key = normalizeHex(col1Data?.output_hex ?? "").slice(0, 32).padEnd(32, "0");
    return [
      {
        label: "Black-box input: PRG output as GGM key",
        formula: "k = G(s)[:128\\text{ bits}]",
        value: key,
        note: "PRF never sees the underlying PRG internals",
      },
      {
        label: "GGM tree traversal for query x",
        formula: "F_k(x) = G_{b_\\ell}(\\cdots G_{b_1}(k)\\cdots)",
        note: "Evaluating query via GGM binary tree",
      },
      {
        label: "PRF output",
        value: truncHex(col2Data.output_hex, 32),
        note: "128-bit pseudorandom value, keyed by PRG-derived key",
      },
    ];
  }
  if (reductionKey === "prf:prg") {
    return [
      {
        label: "Black-box input: query F_k with s‖0 and s‖1",
        formula: "G_k(0) = F_k(0\\,\\|\\,0)\\,\\|\\,F_k(0\\,\\|\\,1)",
        note: "Two PRF oracle calls, seed s=0",
      },
      {
        label: "F_k(s‖0) — left half",
        value: truncHex(col2Data.output_hex ?? "", 32),
        note: "128 bits from PRF oracle call 1",
      },
      {
        label: "PRG output",
        value: truncHex(col2Data.output_hex, 40),
        note: `${col2Data.n_bytes} bytes  |  NIST: ${col2Data.nist_tests?.every(t => t.pass) ? "✓ All pass" : "check results"}`,
      },
    ];
  }
  return [];
}

// ─── Col2 interactive query ───────────────────────────────────────────────────
function Col2Query({ reductionKey, col1Data }) {
  const [qx, setQx] = useState(42);
  const [result, setResult] = useState(null);
  const [loading, setLoading] = useState(false);
  const [err, setErr] = useState(null);

  if (!col1Data) return null;
  if (!["prg:prf", "prf:prg"].includes(reductionKey)) return null;

  const evalQuery = async () => {
    setLoading(true); setResult(null); setErr(null);
    try {
      const key = normalizeHex(col1Data.output_hex).slice(0, 32).padEnd(32, "0");
      if (reductionKey === "prg:prf") {
        const r = await api.prf({ mode: "ggm", key_hex: key, x: Number(qx), input_bits: 8 });
        setResult(r);
      } else {
        const r = await api.prgFromPrf({ key_hex: key, seed_int: Number(qx), n_bytes: 32 });
        setResult(r);
      }
    } catch (e) { setErr(e.message); }
    finally { setLoading(false); }
  };

  return (
    <div className="col2-query-box">
      <div className="col2-query-label">Interactive Query</div>
      <div className="col2-query-row">
        <input
          type="number" value={qx} min={0} max={255}
          onChange={e => setQx(e.target.value)}
          className="input col2-query-input"
          placeholder="x"
        />
        <button className="btn-query" onClick={evalQuery} disabled={loading}>
          {loading ? <Spinner /> : reductionKey === "prg:prf" ? "Eval F_k(x)" : "Eval G_k(x)"}
        </button>
      </div>
      {err && <div className="step-note" style={{ color: "var(--fail-t)" }}>{err}</div>}
      {result && (
        <div className="col2-query-result">
          <div className="step-label">
            {reductionKey === "prg:prf" ? `F_k(${qx})` : `G_k(${qx})`} =
          </div>
          <div className="step-value mono">{truncHex(result.output_hex, 32)}</div>
          {reductionKey === "prg:prf" && result.input_bits && (
            <div className="step-note">
              Path: {Number(qx).toString(2).padStart(result.input_bits, "0").split("").map(b => b === "0" ? "L" : "R").join("→")}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Unsupported pair panel ───────────────────────────────────────────────────
function UnsupportedPair({ source, target, onSwitchDirection }) {
  const pairKey = `${source}:${target}`;
  const msg = UNSUPPORTED_PAIRS[pairKey] ?? `No direct one-step reduction from ${PRIM_LABELS[source]} → ${PRIM_LABELS[target]}.`;
  return (
    <div className="explorer-columns">
      <div className="unsupported-pair-banner">
        <div className="unsupported-pair-title">No Direct Path: {PRIM_LABELS[source]} → {PRIM_LABELS[target]}</div>
        <div className="unsupported-pair-msg">{msg}</div>
        <div className="unsupported-pair-hint">
          Try enabling the <strong>Backward (B→A)</strong> direction toggle, or select an adjacent pair.
        </div>
        <button className="btn-switch-dir" onClick={onSwitchDirection}>Switch to Backward Direction ⇄</button>
      </div>
    </div>
  );
}

// ─── Stub columns ─────────────────────────────────────────────────────────────
function StubColumns({ source, target, meta }) {
  return (
    <div className="explorer-columns">
      <div className="explorer-col stub-col-wrap">
        <div className="stub-col">
          <span style={{ fontSize: 28 }}>⏳</span>
          <span style={{ fontWeight: 600, color: "var(--text-2)" }}>Build {PRIM_LABELS[source]}</span>
          <span className="stub-soon">Not implemented yet (due: PA#{meta.paNum})</span>
          <span className="stub-pa-note">Foundation → {PRIM_LABELS[source]} construction will be available in PA#{meta.paNum}</span>
        </div>
      </div>
      <div className="explorer-connector">
        <div className="connector-line" />
        <span className="connector-arrow">→</span>
      </div>
      <div className="explorer-col stub-col-wrap">
        <div className="stub-col">
          <span style={{ fontSize: 28 }}>⏳</span>
          <span style={{ fontWeight: 600, color: "var(--text-2)" }}>{PRIM_LABELS[source]} → {PRIM_LABELS[target]}</span>
          <span className="stub-soon">Not implemented yet (due: PA#{meta.paNum})</span>
          <span className="stub-pa-note">{meta.theoremName}</span>
        </div>
      </div>
    </div>
  );
}

// ─── Two-column demo ──────────────────────────────────────────────────────────
function DemoColumns({ source, target, foundation, foundationObj, reductionKey, direction, userKey, userQuery, onNavigate, onSwitchDirection }) {
  const [col1Data, setCol1Data] = useState(null);
  const [, setCol2Data] = useState(null);
  const [col1Steps, setCol1Steps] = useState([]);
  const [col2Steps, setCol2Steps] = useState([]);
  const [col1Loading, setCol1Loading] = useState(false);
  const [col2Loading, setCol2Loading] = useState(false);
  const [col1Error, setCol1Error] = useState(null);
  const [col2Error, setCol2Error] = useState(null);
  const [running, setRunning] = useState(false);

  useEffect(() => {
    setCol1Data(null); setCol2Data(null);
    setCol1Steps([]); setCol2Steps([]);
    setCol1Error(null); setCol2Error(null);
  }, [source, target, foundation, userKey, userQuery]);

  const runDemoRef = useRef(null);

  const effectiveKey = getEffectiveReductionKey(source, target, direction);
  const backwardKey = direction === "backward" ? `${target}:${source}` : null;
  const meta = REDUCTIONS[reductionKey] ?? REDUCTIONS[effectiveKey] ?? (backwardKey ? REDUCTIONS[backwardKey] : undefined);

  useEffect(() => {
    if (!meta?.live) return;
    const timer = setTimeout(() => { runDemoRef.current?.(); }, 700);
    return () => clearTimeout(timer);
  }, [source, target, foundation, userKey, userQuery, reductionKey, meta]);

  const hasReverseRoute = direction === "backward" && isRouteSupported(source, target, "backward");
  const unsupported = !meta && !hasReverseRoute && UNSUPPORTED_PAIRS[reductionKey] !== undefined;
  const noPath = !meta && !hasReverseRoute && !UNSUPPORTED_PAIRS[reductionKey];

  const route = planRoute(source, target, direction);
  if (!meta && route) {
    const routeMeta = {
      theorem: `\\text{${PRIM_LABELS[source]}} \\Rightarrow \\text{${PRIM_LABELS[target]}}`,
      theoremName: `Multi-hop: ${describeRoute(route, PRIM_LABELS)} (${route.length} steps)`,
      paNum: 99,
      live: false,
    };
    return (
      <>
        <div className="reduction-formula-bar">
          <Math expr={routeMeta.theorem} />
          <span className="reduction-theorem-name">{routeMeta.theoremName}</span>
        </div>
        <StubColumns source={source} target={target} meta={routeMeta} />
      </>
    );
  }

  if (unsupported || noPath) return <UnsupportedPair source={source} target={target} onSwitchDirection={onSwitchDirection} />;
  if (!meta) return <UnsupportedPair source={source} target={target} onSwitchDirection={onSwitchDirection} />;
  if (!meta.live) {
    return (
      <>
        <div className="reduction-formula-bar">
          <Math expr={meta.theorem} />
          <span className="reduction-theorem-name">{meta.theoremName}</span>
        </div>
        <StubColumns source={source} target={target} meta={meta} />
      </>
    );
  }

  const runDemo = async () => {
    setRunning(true);
    setCol1Data(null); setCol2Data(null);
    setCol1Steps([]); setCol2Steps([]);
    setCol1Error(null); setCol2Error(null);

    const keyHex = normalizeHex(userKey).padEnd(32, "0").slice(0, 32);
    setCol1Loading(true);
    let c1 = null;
    let sourceOracle = null;
    try {
      if (source === "owf") {
        c1 = foundation === "dlp"
          ? await foundationObj.asOWF(userQuery || "42")
          : await foundationObj.asOWF(keyHex);
        sourceOracle = {
          type: "owf",
          outputHex: c1.output_hex,
          asPRG: (seed_hex, output_bits) => foundationObj.asPRG(seed_hex, output_bits),
        };
      } else if (source === "prg") {
        c1 = await foundationObj.asPRG(keyHex, 128);
        sourceOracle = {
          type: "prg",
          outputHex: c1.output_hex,
          asPRF: (key_hex, x, input_bits) => api.prf({ mode: "ggm", key_hex, x, input_bits }),
        };
      } else if (source === "prf") {
        if (!foundationObj.asPRF) {
          throw new Error(`${foundationObj.name} does not directly provide a PRF. Use AES foundation for PRF.`);
        }
        c1 = await foundationObj.asPRF(keyHex, parseInt(userQuery || "42"), 8);
        sourceOracle = {
          type: "prf",
          outputHex: c1.output_hex,
          asPRGFromPRF: (key_hex, seed_int, n_bytes) => api.prgFromPrf({ key_hex, seed_int, n_bytes }),
        };
      }
      setCol1Data(c1);
      setCol1Steps(buildCol1Steps(source, foundation, c1, keyHex));
    } catch (e) {
      setCol1Error(e.message);
      setCol1Loading(false);
      setRunning(false);
      return;
    }
    setCol1Loading(false);

    setCol2Loading(true);
    try {
      let c2 = null;
      if (reductionKey === "owf:prg") {
        const seed = normalizeHex(sourceOracle.outputHex).slice(0, 32).padEnd(32, "0");
        c2 = await sourceOracle.asPRG(seed, 128);
      } else if (reductionKey === "prg:prf") {
        const key = normalizeHex(sourceOracle.outputHex).slice(0, 32).padEnd(32, "0");
        c2 = await sourceOracle.asPRF(key, parseInt(userQuery || "42"), 8);
      } else if (reductionKey === "prf:prg") {
        const key = normalizeHex(sourceOracle.outputHex).slice(0, 32).padEnd(32, "0");
        c2 = await sourceOracle.asPRGFromPRF(key, 0, 32);
      }
      setCol2Data(c2);
      setCol2Steps(buildCol2Steps(reductionKey, c1, c2));
    } catch (e) {
      setCol2Error(e.message);
    }
    setCol2Loading(false);
    setRunning(false);
  };

  runDemoRef.current = runDemo;

  const col1Label = direction === "backward"
    ? `Step 1 — Build ${PRIM_LABELS[target]} (backward source)`
    : `Step 1 — Build ${PRIM_LABELS[source]}`;
  const col2Label = direction === "backward"
    ? `Step 2 — Reduce ${PRIM_LABELS[target]} → ${PRIM_LABELS[source]} (backward)`
    : `Step 2 — Reduce ${PRIM_LABELS[source]} → ${PRIM_LABELS[target]}`;

  return (
    <>
      <div className="reduction-formula-bar">
        <Math expr={meta.theorem} />
        <span className="reduction-theorem-name">{meta.theoremName}</span>
      </div>

      <div className="explorer-columns">
        <div className="explorer-col">
          <div className="explorer-col-header">
            <div className="explorer-col-label">{col1Label}</div>
            <div className="explorer-col-title">
              Construct {PRIM_LABELS[source]} from {foundation === "aes" ? "AES-128" : "DLP"} foundation
            </div>
          </div>
          <div className="col-input-row">
            <label className="col-input-label">Key / Seed (hex)</label>
            <input className="input col-input-field" value={userKey} readOnly placeholder="hex key or seed" />
          </div>
          <div className="explorer-col-body">
            {!col1Data && !col1Loading && !col1Error && (
              <div className="col-empty-hint">Click <strong>Run Demo</strong> to evaluate with real values</div>
            )}
            {col1Loading && <div className="col-loading"><Spinner /> Building {PRIM_LABELS[source]}…</div>}
            {col1Error && (
              <div className="result-error" style={{ fontSize: 13 }}>
                <span className="result-error-label">Error</span> {col1Error}
              </div>
            )}
            {col1Steps.length > 0 && <StepTrace steps={col1Steps} />}
          </div>
        </div>

        <div className="explorer-connector">
          <div className="connector-line" />
          <div className="connector-mid">
            <span className="connector-arrow">→</span>
            <span className="connector-label">black<br />box</span>
          </div>
          <div className="connector-line" />
        </div>

        <div className="explorer-col">
          <div className="explorer-col-header">
            <div className="explorer-col-label">{col2Label}</div>
            <div className="explorer-col-title">
              Build {PRIM_LABELS[target]} using {PRIM_LABELS[source]} as black box
            </div>
          </div>
          <div className="col-input-row">
            <label className="col-input-label">Query / Message</label>
            <input className="input col-input-field" value={userQuery} readOnly placeholder="message or query value" />
          </div>
          <div className="explorer-col-body">
            {meta.blackBoxNote && col1Data && (
              <div className="black-box-note">
                <span className="black-box-icon">⬛</span>
                <span>{meta.blackBoxNote}</span>
              </div>
            )}
            {!col1Data && !col2Loading && !col2Error && (
              <div className="col-empty-hint">Waiting for {PRIM_LABELS[source]} output…</div>
            )}
            {col2Loading && <div className="col-loading"><Spinner /> Running reduction…</div>}
            {col2Error && (
              <div className="result-error" style={{ fontSize: 13 }}>
                <span className="result-error-label">Error</span> {col2Error}
              </div>
            )}
            {col2Steps.length > 0 && <StepTrace steps={col2Steps} />}
            <Col2Query reductionKey={reductionKey} col1Data={col1Data} />
          </div>
        </div>
      </div>

      <div className="explorer-actions">
        <button className="btn-demo" onClick={runDemo} disabled={running}>
          {running ? <><Spinner /> Running…</> : "▶  Run Demo"}
        </button>
        {meta.paLink && (
          <button className="btn-open-l2" onClick={() => onNavigate?.(meta.paLink)}>
            Open {meta.paLink.toUpperCase()} Detail ↗
          </button>
        )}
      </div>
    </>
  );
}

// ─── Proof accordion ──────────────────────────────────────────────────────────
function ProofAccordion({ reductionKey, source, target, direction }) {
  const [open, setOpen] = useState(false);
  const effectiveKey = getEffectiveReductionKey(source, target, direction);
  const meta = REDUCTIONS[reductionKey] ?? REDUCTIONS[effectiveKey];
  const route = planRoute(source, target, direction);
  const isMultiHop = route && route.length > 1;
  const unsupportedMsg = !meta
    ? (UNSUPPORTED_PAIRS[reductionKey] ?? (route ? null : null))
    : null;

  if (!meta && !unsupportedMsg && !route) return null;

  return (
    <div className="proof-accordion">
      <button className="proof-accordion-btn" onClick={() => setOpen(o => !o)}>
        <span>
          {meta
            ? <>Proof Sketch — <span style={{ fontFamily: "var(--font-mono)", fontSize: 12.5 }}>{meta.theoremName}</span></>
            : <>Unsupported Pair — {PRIM_LABELS[source]} → {PRIM_LABELS[target]}</>
          }
        </span>
        <span className={`proof-chevron ${open ? "proof-chevron-open" : ""}`}>▼</span>
      </button>
      {open && meta && (
        <div className="proof-body">
          <div className="proof-theorem-row">
            <span style={{ background: "var(--indigo-50)", border: "1px solid var(--indigo-100)", borderRadius: "var(--r-md)", padding: "4px 12px" }}>
              <Math expr={meta.theorem} />
            </span>
            <span className="proof-theorem-name">{meta.theoremName}</span>
            <span className="proof-pa-badge">PA #{meta.paNum}</span>
          </div>
          <div style={{ marginTop: 6 }}><Math expr={meta.formula} block /></div>
          <p className="proof-sketch">{meta.proofSketch}</p>
          <div className="proof-security-claim">
            <span className="proof-security-label">Security Reduction:</span>
            <span className="proof-security-text">{meta.securityClaim}</span>
          </div>
          {meta.blackBoxNote && (
            <div className="proof-blackbox-note">
              <span style={{ marginRight: 6 }}>⬛</span>
              <span>{meta.blackBoxNote}</span>
            </div>
          )}
          <div className="proof-chain-summary">
            <div className="proof-chain-title">Reduction Chain</div>
            <div className="proof-chain-row">
              <span className="proof-chain-node proof-chain-foundation">Foundation (AES / DLP)</span>
              <span className="proof-chain-arrow">→</span>
              <span className="proof-chain-node proof-chain-source">{PRIM_LABELS[source]}</span>
              {route && route.map((step, i) => (
                <span key={i} style={{ display: "flex", alignItems: "center" }}>
                  <span className="proof-chain-arrow">{direction === "backward" ? "⟵" : "→"}</span>
                  <span className={`proof-chain-node ${i === route.length - 1 ? "proof-chain-target" : "proof-chain-source"}`}>
                    {PRIM_LABELS[step.to]}
                  </span>
                </span>
              ))}
            </div>
            <div className="proof-chain-steps">
              <div><strong>Leg 1:</strong> Foundation → {PRIM_LABELS[source]} (Column 1)</div>
              {route && route.map((step, i) => (
                <div key={i}>
                  <strong>Leg {i + 2}:</strong>{" "}
                  {PRIM_LABELS[step.from]} {direction === "backward" ? "⟵" : "→"} {PRIM_LABELS[step.to]}
                  {i === 0 ? ` via ${meta.theoremName} (Column 2)` : " (stub — upcoming PA)"}
                </div>
              ))}
              {isMultiHop && (
                <div className="proof-chain-multihop-note">
                  Full route: {describeRoute(route, PRIM_LABELS)} — intermediate steps are stubs pending future PAs.
                </div>
              )}
            </div>
          </div>
        </div>
      )}
      {open && (unsupportedMsg || (!meta && route)) && (
        <div className="proof-body">
          {unsupportedMsg && <p className="proof-sketch">{unsupportedMsg}</p>}
          {!meta && route && (
            <div className="proof-chain-summary">
              <div className="proof-chain-title">Planned Route (multi-hop)</div>
              <div className="proof-chain-row">
                {[source, ...route.map(s => s.to)].map((node, i, arr) => (
                  <span key={node} style={{ display: "flex", alignItems: "center" }}>
                    <span className={`proof-chain-node ${i === 0 ? "proof-chain-source" : i === arr.length - 1 ? "proof-chain-target" : "proof-chain-source"}`}>
                      {PRIM_LABELS[node]}
                    </span>
                    {i < arr.length - 1 && <span className="proof-chain-arrow">→</span>}
                  </span>
                ))}
              </div>
              <p className="proof-sketch" style={{ marginTop: 8 }}>
                {describeRoute(route, PRIM_LABELS)} — {route.length}-hop composed reduction. Intermediate steps pending future PAs.
              </p>
            </div>
          )}
          {unsupportedMsg && (
            <div className="proof-security-claim">
              <span className="proof-security-label">Suggestion:</span>
              <span className="proof-security-text">Use the Backward (B→A) toggle or select an adjacent pair in the clique graph.</span>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

// ─── Clique chain ─────────────────────────────────────────────────────────────
function CliqueChain({ foundation, activePair }) {
  const nodes = [
    { label: foundation === "aes" ? "AES" : "DLP", key: "foundation", type: "foundation" },
    { label: "OWF",  key: "owf",  type: "impl" },
    { label: "OWP",  key: "owp",  type: "impl" },
    { label: "PRG",  key: "prg",  type: "impl" },
    { label: "PRF",  key: "prf",  type: "impl" },
    { label: "PRP",  key: "prp",  type: "upcoming" },
    { label: "MAC",  key: "mac",  type: "upcoming" },
    { label: "CRHF", key: "crhf", type: "upcoming" },
    { label: "HMAC", key: "hmac", type: "upcoming" },
  ];
  return (
    <div className="clique-chain" style={{ flexWrap: "wrap", rowGap: 6 }}>
      {nodes.map((node, i) => (
        <span key={node.key} style={{ display: "flex", alignItems: "center" }}>
          <span className={`clique-chain-node ${
            node.type === "foundation" ? "chain-foundation" :
            node.type === "impl" ? "chain-implemented" : "chain-upcoming"
          } ${activePair && (node.key === activePair[0] || node.key === activePair[1]) ? "chain-active" : ""}`}>
            {node.label}
          </span>
          {i < nodes.length - 1 && <span className="clique-chain-arrow">→</span>}
        </span>
      ))}
    </div>
  );
}

// ─── Clique Map Modal ─────────────────────────────────────────────────────────
const CLIQUE_REDUCTIONS = [
  {
    group: "Minicrypt Core",
    color: "#4f46e5",
    items: [
      { chain: "OWF ⇒ PRG", theorem: "HILL Theorem (Goldreich–Levin, 1989)", note: "Hard-core bit extraction from any OWF gives a 1-bit-stretching PRG" },
      { chain: "OWF ⇒ OWP", theorem: "DLP Bijection", note: "f(x) = gˣ mod p is a bijection on ℤq — OWF immediately becomes OWP" },
      { chain: "OWP ⇒ PRG", theorem: "Hard-Core Predicate", note: "G(x) = (f(x), b(x)) where b is the Goldreich–Levin hard-core bit" },
      { chain: "PRG ⇒ PRF", theorem: "GGM Tree (Goldreich–Goldwasser–Micali, 1986)", note: "Binary tree of depth ℓ; each node doubles output via PRG" },
      { chain: "OWP ⇒ PRF", theorem: "Composed: OWP → PRG → PRF", note: "Two-hop reduction — both hops negligible" },
      { chain: "PRF ⇒ PRG", theorem: "Trivial (backward)", note: "G_k(s) = F_k(s‖0) ‖ F_k(s‖1) — any PRF distinguisher breaks PRF" },
      { chain: "PRF ⇒ PRP", theorem: "Luby–Rackoff (1988)", note: "3-round Feistel with PRF as round function yields a secure PRP" },
      { chain: "PRF ⇒ MAC", theorem: "PRF-MAC", note: "Mac_k(m) = F_k(m) is EUF-CMA secure; forgery breaks PRF" },
      { chain: "PRP ⇒ MAC", theorem: "PRP-MAC (via switching lemma)", note: "|Adv_PRP − Adv_PRF| ≤ q²/2ⁿ; then apply PRF-MAC" },
      { chain: "CRHF ⇒ HMAC", theorem: "HMAC Construction", note: "H(k‖H(k‖m)) — security from collision-resistance + PRF of compression" },
      { chain: "HMAC ⇒ MAC", theorem: "HMAC is a MAC", note: "HMAC satisfies EUF-CMA under standard CRHF + PRF assumptions" },
    ],
  },
  {
    group: "Symmetric ⇒ Asymmetric",
    color: "#0891b2",
    items: [
      { chain: "PRF + CRHF ⇒ CPA-Enc", theorem: "CTR-mode / CBC-mode", note: "Use PRF as keystream; semantic security from PRF indistinguishability" },
      { chain: "MAC + CPA-Enc ⇒ CCA-Enc", theorem: "Encrypt-then-MAC", note: "Any secure MAC + CPA-secure scheme gives CCA-secure encryption" },
    ],
  },
  {
    group: "Public-Key Cryptography",
    color: "#dc2626",
    items: [
      { chain: "CCA-Enc ⇒ PKC", theorem: "Public-Key Encryption", note: "CCA-secure symmetric enc can bootstrap to PKC via OT/trapdoor" },
      { chain: "PKC ⇒ Digital Signature", theorem: "Sign from PKC", note: "Any PKC scheme implies a signature scheme (non-repudiation)" },
      { chain: "PKC ⇒ CCA-PKC", theorem: "Active-Secure PKC", note: "Standard constructions (OAEP, etc.) lift PKC to CCA-PKC" },
    ],
  },
  {
    group: "Multi-Party Computation",
    color: "#7c3aed",
    items: [
      { chain: "CCA-PKC ⇒ OT", theorem: "Oblivious Transfer", note: "OT is the fundamental 2-party primitive; implied by CCA-PKC" },
      { chain: "OT ⇒ Secure AND", theorem: "MPC Gate", note: "1-out-of-2 OT enables private AND evaluation" },
      { chain: "OT ⇒ Secure XOR", theorem: "Free XOR", note: "XOR is free in most MPC frameworks (information-theoretic)" },
      { chain: "Secure AND + Secure XOR ⇒ All 2-Party MPC", theorem: "Completeness (Yao, 1986)", note: "AND + XOR is a complete gate set for any boolean circuit" },
    ],
  },
];

function CliqueMapModal({ onClose }) {
  useEffect(() => {
    const onKey = (e) => { if (e.key === "Escape") onClose(); };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  return (
    <div className="cmap-backdrop" onClick={e => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="cmap-modal">
        {/* Header */}
        <div className="cmap-header">
          <div>
            <span className="cmap-chip">CS8.401</span>
            <span className="cmap-title">Minicrypt Clique — Reference Map</span>
          </div>
          <button className="cmap-close" onClick={onClose} title="Close (Esc)">✕</button>
        </div>

        {/* Body: PDF + Notes */}
        <div className="cmap-body">
          {/* PDF panel */}
          <div className="cmap-pdf-panel">
            <div className="cmap-panel-label">Clique Diagram (Lecture Notes p.4)</div>
            <iframe
              className="cmap-pdf-frame"
              src="/pois-project.pdf#page=4&toolbar=0&navpanes=0&scrollbar=0"
              title="Minicrypt Clique Diagram"
            />
          </div>

          {/* Notes panel */}
          <div className="cmap-notes-panel">
            <div className="cmap-panel-label">All Reductions</div>
            <div className="cmap-notes-scroll">
              {CLIQUE_REDUCTIONS.map(group => (
                <div key={group.group} className="cmap-group">
                  <div className="cmap-group-header" style={{ borderLeftColor: group.color, color: group.color }}>
                    {group.group}
                  </div>
                  {group.items.map(item => (
                    <div key={item.chain} className="cmap-item">
                      <div className="cmap-item-chain">{item.chain}</div>
                      <div className="cmap-item-theorem">{item.theorem}</div>
                      <div className="cmap-item-note">{item.note}</div>
                    </div>
                  ))}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  );
}

// ─── PA0 Page ─────────────────────────────────────────────────────────────────
export function PA0Page({ foundation, onFoundationChange, onBack, onNavigate }) {
  const [source, setSource]       = useState("owf");
  const [target, setTarget]       = useState("prg");
  const [direction, setDirection] = useState("forward");
  const [userKey,   setUserKey]   = useState("00112233445566778899aabbccddeeff");
  const [userQuery, setUserQuery] = useState("42");
  const [showCliqueMap, setShowCliqueMap] = useState(false);

  const foundationObj = getFoundation(foundation);
  const validTargets  = getValidTargets(source, direction);

  const handleSourceChange = (newSource) => {
    setSource(newSource);
    const valid = getValidTargets(newSource, direction);
    if (!valid.includes(target)) setTarget(valid[0] ?? "prg");
  };

  const handleDirectionChange = (newDir) => {
    setDirection(newDir);
    const newSource = target;
    const newTarget = source;
    setSource(newSource);
    const validInNew = getValidTargets(newSource, newDir);
    setTarget(validInNew.includes(newTarget) ? newTarget : (validInNew[0] ?? newTarget));
  };

  const handleSwitchDirection = () => {
    handleDirectionChange(direction === "forward" ? "backward" : "forward");
  };

  const reductionKey = `${source}:${target}`;

  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      {/* Breadcrumb */}
      <div className="l2-topbar">
        <button className="breadcrumb-btn" onClick={onBack}>← Explorer Home</button>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current">PA #0 — Minicrypt Clique Explorer</span>
      </div>

      <div className="explorer-wrap">
        {/* Header */}
        <div className="explorer-hero">
          <div className="explorer-course-chip">CS8.401 — Minicrypt Clique</div>
          <h1 className="explorer-title">Cryptographic Reduction Explorer</h1>
          <p className="explorer-tagline">
            Select a reduction pair, click <strong>Run Demo</strong>, and watch how each primitive
            is constructed from its predecessor using only black-box access.
          </p>
          <div className="foundation-row">
            <span className="foundation-label">Foundation:</span>
            <SegControl
              value={foundation}
              onChange={onFoundationChange}
              options={[{ value: "aes", label: "AES-128 (PRP)" }, { value: "dlp", label: "DLP (gˣ mod p)" }]}
            />
          </div>
          <CliqueChain foundation={foundation} activePair={[source, target]} />
          <div style={{ marginTop: 14 }}>
            <button className="cmap-open-btn" onClick={() => setShowCliqueMap(true)}>
              View Clique Map &amp; All Reductions
            </button>
          </div>
        </div>

        {showCliqueMap && <CliqueMapModal onClose={() => setShowCliqueMap(false)} />}

        <hr style={{ border: "none", borderTop: "1px solid var(--border-1)", margin: "0 0 20px" }} />

        {/* Direction */}
        <div className="direction-row">
          <span className="direction-label">Direction:</span>
          <SegControl
            value={direction}
            onChange={handleDirectionChange}
            options={[
              { value: "forward",  label: "Forward (A → B)" },
              { value: "backward", label: "Backward (B → A)" },
            ]}
          />
          <span className="direction-hint">
            {direction === "forward"
              ? "Construct B from A — shows how each primitive implies the next"
              : "Break A from B — shows how breaking B would break A"}
          </span>
        </div>

        <hr style={{ border: "none", borderTop: "1px solid var(--border-1)", margin: "0 0 20px" }} />

        {/* Pair selector */}
        <div className="pair-selector-row">
          <div className="prim-select-wrap">
            <span className="prim-select-label">Source Primitive A</span>
            <select className="prim-select" value={source} onChange={e => handleSourceChange(e.target.value)}>
              {SOURCE_OPTIONS.map(o => <option key={o.value} value={o.value}>{o.label}</option>)}
            </select>
          </div>
          <span className="pair-arrow">{direction === "forward" ? "⟶" : "⟵"}</span>
          <div className="prim-select-wrap">
            <span className="prim-select-label">Target Primitive B</span>
            <select className="prim-select" value={target} onChange={e => setTarget(e.target.value)}>
              {validTargets.length === 0
                ? <option value="">— no direct target —</option>
                : validTargets.map(t => <option key={t} value={t}>{PRIM_LABELS[t]} — {t.toUpperCase()}</option>)
              }
            </select>
          </div>
        </div>

        {/* User inputs */}
        <div className="user-inputs-row">
          <div className="user-input-wrap">
            <label className="user-input-label">Key / Seed (hex)</label>
            <input
              className="input user-input-field"
              value={userKey}
              onChange={e => setUserKey(e.target.value)}
              placeholder="e.g. 00112233445566778899aabbccddeeff"
              maxLength={64}
            />
          </div>
          <div className="user-input-wrap">
            <label className="user-input-label">Query / Message</label>
            <input
              className="input user-input-field"
              value={userQuery}
              onChange={e => setUserQuery(e.target.value)}
              placeholder="e.g. 42"
            />
          </div>
        </div>

        {/* Two-column live demo */}
        <DemoColumns
          source={source}
          target={target}
          foundation={foundation}
          foundationObj={foundationObj}
          reductionKey={reductionKey}
          direction={direction}
          userKey={userKey}
          userQuery={userQuery}
          onNavigate={onNavigate}
          onSwitchDirection={handleSwitchDirection}
        />

        {/* Proof accordion */}
        <ProofAccordion reductionKey={reductionKey} source={source} target={target} direction={direction} />
      </div>
    </div>
  );
}
