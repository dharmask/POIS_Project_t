import { useState, useEffect, useRef } from "react";
import { api } from "./api";
import {
  useAsync, Math, Spinner, Field, SegControl,
  ResultArea, PanelCard, Badge,
  OWFResult, PRGResult, NISTResult, PRFResult, PRGFromPRFResult, DistGameResult,
  PRPResult, ModesResult, PaddingOracleResult, MACResult, LengthExtResult, EUFCMAResult,
  RSAKeygenResult, RSACryptResult, RSASignResult, RSACPAResult,
  DHExchangeResult, MITMResult, AuthDHResult,
  OWFHardnessResult, OWFFromPRGResult,
} from "./shared";

// ─── OWF Panel ────────────────────────────────────────────────────────────────
export function OWFPanel({ foundation = "aes" }) {
  const [mode, setMode]     = useState(foundation ?? "aes");
  const [x, setX]           = useState(42);
  const [keyHex, setKeyHex] = useState("00112233445566778899aabbccddeeff");
  const { loading, data, error, run } = useAsync(api.owf);

  const submit = () => run({
    mode,
    x:       mode === "dlp" ? Number(x) : undefined,
    key_hex: mode === "aes" ? keyHex    : undefined,
  });

  const formula = mode === "dlp"
    ? "f(x) = g^x \\bmod p"
    : "f(k) = \\text{AES}_k(0^{128}) \\oplus k";

  return (
    <PanelCard
      title="One-Way Function"
      formula={formula}
      desc="Security reduces to DLP hardness (DLP mode) or AES pseudorandomness (AES mode)."
      inputContent={
        <>
          <Field label="Construction">
            <SegControl value={mode} onChange={setMode} options={[
              { value: "dlp", label: "DLP" },
              { value: "aes", label: "AES" },
            ]} />
          </Field>
          {mode === "dlp" ? (
            <Field label="Exponent x" hint={<>Computes <Math expr="g^x \bmod p" />, g=2, 768-bit safe prime</>}>
              <input type="number" value={x} onChange={e => setX(e.target.value)} className="input" style={{ width: "120px" }} />
            </Field>
          ) : (
            <Field label="Key k" hint="16 bytes — 32 hex characters">
              <input value={keyHex} onChange={e => setKeyHex(e.target.value)} className="input mono" />
            </Field>
          )}
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Computing…</> : "Compute OWF"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <OWFResult data={data} />}
        </ResultArea>
      }
    />
  );
}

// ─── PRG Panel ────────────────────────────────────────────────────────────────
export function PRGPanel({ foundation = "aes" }) {
  const [mode, setMode]       = useState(foundation ?? "aes");
  const [seedHex, setSeedHex] = useState("deadbeefcafebabe0102030405060708");
  // Slider: 64–2048 bits (8–256 bytes), step 8
  const [bits, setBits]       = useState(256);
  const { loading, data, error, run } = useAsync(api.prg);
  const { loading: nistLoading, data: nistData, error: nistError, run: runNist } = useAsync(api.nist);

  // Live auto-run on seed/bits/mode change (700ms debounce)
  useEffect(() => {
    const timer = setTimeout(() => {
      run({ mode, seed_hex: seedHex, output_bits: Number(bits) });
    }, 700);
    return () => clearTimeout(timer);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [mode, seedHex, bits]);

  const runQuickNist = () => runNist({ mode, seed_hex: seedHex, n_bits: 10000 });

  return (
    <PanelCard
      title="Pseudorandom Generator"
      formula={"G(s) = b(s) \\,\\|\\, b(f(s)) \\,\\|\\, \\cdots \\,\\|\\, b(f^{\\ell}(s))"}
      desc="GL hard-core bit: b(xᵢ) = ⟨xᵢ, r⟩ mod 2. State iteration: xᵢ₊₁ = f(xᵢ)."
      inputContent={
        <>
          <Field label="OWF Foundation">
            <SegControl value={mode} onChange={setMode} options={[
              { value: "aes", label: "AES" },
              { value: "dlp", label: "DLP" },
            ]} />
          </Field>
          <Field label="Seed (hex)" hint={mode === "aes" ? "16 bytes = 32 hex chars" : "Any hex integer"}>
            <input value={seedHex} onChange={e => setSeedHex(e.target.value)} className="input mono" />
          </Field>
          <Field label={`Output bits: ${bits}`} hint="64 – 2048 bits (8–256 bytes)">
            <input
              type="range"
              value={bits}
              min={64}
              max={2048}
              step={8}
              onChange={e => setBits(Number(e.target.value))}
              className="range-slider"
              style={{ width: "100%" }}
            />
            <span className="range-value-label">{bits} bits = {bits / 8} bytes</span>
          </Field>
          <div style={{ display: "flex", gap: "8px", alignItems: "center", flexWrap: "wrap" }}>
            {loading && <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}><Spinner /> Auto-updating…</span>}
            <button className="btn-secondary" onClick={runQuickNist} disabled={nistLoading} style={{ marginLeft: "auto" }}>
              {nistLoading ? <><Spinner /> Testing…</> : "Quick NIST Test"}
            </button>
          </div>
          {nistData && (
            <div className={`quick-nist-badge ${nistData.overall_pass ? "nist-pass" : "nist-fail"}`}>
              NIST SP 800-22: {nistData.overall_pass ? "✓ ALL PASS" : "✗ FAIL"} —{" "}
              {nistData.tests.map(t => `${t.test}: ${t.pass ? "✓" : "✗"}`).join(", ")}
            </div>
          )}
          {nistError && <div className="quick-nist-badge nist-fail">NIST Error: {nistError}</div>}
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <PRGResult data={data} />}
        </ResultArea>
      }
    />
  );
}

// ─── NIST Panel ───────────────────────────────────────────────────────────────
export function NISTPanel({ foundation = "aes" }) {
  const [mode, setMode]       = useState(foundation ?? "aes");
  const [seedHex, setSeedHex] = useState("aabbccddeeff00112233445566778899");
  const [nBits, setNBits]     = useState(20000);
  const { loading, data, error, run } = useAsync(api.nist);

  const submit = () => run({ mode, seed_hex: seedHex, n_bits: Number(nBits) });

  return (
    <PanelCard
      title="NIST SP 800-22 Statistical Tests"
      formula={"P \\geq 0.01 \\Rightarrow \\textup{PASS}"}
      desc="Frequency (monobit), Runs, Serial (m=2). All pure Python — no scipy."
      fullWidth
      inputContent={
        <>
          <Field label="PRG Mode">
            <SegControl value={mode} onChange={setMode} options={[
              { value: "aes", label: "AES PRG" },
              { value: "dlp", label: "DLP PRG" },
            ]} />
          </Field>
          <Field label="Seed (hex)">
            <input value={seedHex} onChange={e => setSeedHex(e.target.value)} className="input mono" />
          </Field>
          <Field label="Bits to test" hint="Min 100 · Recommended ≥ 10000">
            <input type="number" value={nBits} min={100} max={1000000} onChange={e => setNBits(e.target.value)} className="input" style={{ width: "110px" }} />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Running tests…</> : "Run NIST Tests"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <NISTResult data={data} />}
        </ResultArea>
      }
    />
  );
}

// ─── OWF Hardness Panel ───────────────────────────────────────────────────────
export function OWFHardnessPanel({ foundation = "dlp" }) {
  const [mode, setMode]       = useState(foundation === "aes" ? "aes" : "dlp");
  const [nTrials, setNTrials] = useState(50);
  const { loading, data, error, run } = useAsync(api.owfHardness);

  const submit = () => run({ mode, n_trials: Number(nTrials) });

  return (
    <PanelCard
      title="OWF Hardness Verification"
      formula={"\\Pr[f(\\text{guess}) = f(x)] \\approx 0"}
      desc={
        "Demonstrates that random inversion of f(x) succeeds with negligible probability. " +
        "Adversary picks random guess x′ and checks f(x′) == f(x). " +
        "Success rate ≈ 0 confirms one-wayness."
      }
      inputContent={
        <>
          <Field label="OWF Construction">
            <SegControl value={mode} onChange={setMode} options={[
              { value: "dlp", label: "DLP (g^x mod p)" },
              { value: "aes", label: "AES (f(k) = AES_k(0) ⊕ k)" },
            ]} />
          </Field>
          <Field label="Number of trials" hint="10 – 200 random inversion attempts">
            <input
              type="range"
              value={nTrials}
              min={10}
              max={200}
              step={10}
              onChange={e => setNTrials(Number(e.target.value))}
              className="range-slider"
              style={{ width: "100%" }}
            />
            <span className="range-value-label">{nTrials} trials</span>
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Running…</> : "Run Hardness Demo"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <OWFHardnessResult data={data} />}
        </ResultArea>
      }
    />
  );
}

// ─── OWF-from-PRG Panel (Backward reduction: PRG → OWF) ──────────────────────
export function OWFFromPRGPanel({ foundation = "aes" }) {
  const [mode, setMode]       = useState(foundation ?? "aes");
  const [seedHex, setSeedHex] = useState("deadbeefcafebabe0102030405060708");
  const [outputBits, setOutputBits] = useState(256);
  const { loading, data, error, run } = useAsync(api.owfFromPrg);

  const submit = () => run({ mode, seed_hex: seedHex, output_bits: Number(outputBits) });

  return (
    <PanelCard
      title="PRG → OWF (Backward Reduction)"
      formula={"f(s) = G(s)"}
      desc={
        "Backward reduction: any PRG G is itself a OWF. " +
        "Define f(s) = G(s). " +
        "If an adversary could invert f, they recover the seed s " +
        "from the PRG output itself — contradicting pseudorandomness."
      }
      inputContent={
        <>
          <Field label="PRG Foundation">
            <SegControl value={mode} onChange={setMode} options={[
              { value: "aes", label: "AES PRG" },
              { value: "dlp", label: "DLP PRG" },
            ]} />
          </Field>
          <Field label="Seed (hex)" hint={mode === "aes" ? "16 bytes = 32 hex chars" : "Any hex integer"}>
            <input value={seedHex} onChange={e => setSeedHex(e.target.value)} className="input mono" />
          </Field>
          <Field label={`Output bits: ${outputBits}`} hint="64 – 2048 bits">
            <input
              type="range"
              value={outputBits}
              min={64}
              max={2048}
              step={64}
              onChange={e => setOutputBits(Number(e.target.value))}
              className="range-slider"
              style={{ width: "100%" }}
            />
            <span className="range-value-label">{outputBits} bits</span>
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Computing…</> : "Run Backward Reduction"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <OWFFromPRGResult data={data} />}
        </ResultArea>
      }
    />
  );
}

// ─── PRF Panel ────────────────────────────────────────────────────────────────
export function PRFPanel() {
  const [mode, setMode]     = useState("ggm");
  const [keyHex, setKeyHex] = useState("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
  const [x, setX]           = useState(42);
  const [inBits, setInBits] = useState(8);
  const { loading, data, error, run } = useAsync(api.prf);

  const submit = () => run({ mode, key_hex: keyHex, x: Number(x), input_bits: Number(inBits) });

  const formula = mode === "ggm"
    ? "F_k(b_1\\cdots b_\\ell)=G_{b_\\ell}(\\cdots G_{b_1}(k)\\cdots)"
    : "F_k(x) = \\text{AES}_k(x)";

  return (
    <PanelCard
      title="Pseudorandom Function"
      formula={formula}
      desc="GGM builds a PRF from a length-doubling PRG. AES plug-in uses the PRP–PRF switching lemma."
      inputContent={
        <>
          <Field label="Construction">
            <SegControl value={mode} onChange={setMode} options={[
              { value: "ggm", label: "GGM Tree" },
              { value: "aes", label: "AES PRF" },
            ]} />
          </Field>
          <Field label="Key k" hint="16 bytes = 32 hex chars">
            <input value={keyHex} onChange={e => setKeyHex(e.target.value)} className="input mono" />
          </Field>
          <Field label="Input x">
            <input type="number" value={x} onChange={e => setX(e.target.value)} className="input" style={{ width: "110px" }} />
          </Field>
          <Field label="Input bit-width" hint={<>Domain size = <Math expr="2^n" /></>}>
            <input type="number" value={inBits} min={1} max={64} onChange={e => setInBits(e.target.value)} className="input" style={{ width: "80px" }} />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Evaluating…</> : "Evaluate PRF"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <PRFResult data={data} />}
        </ResultArea>
      }
    />
  );
}

// ─── PRG from PRF Panel ───────────────────────────────────────────────────────
export function PRGFromPRFPanel() {
  const [keyHex, setKeyHex] = useState("cafebabe00112233445566778899aabb");
  const [seed, setSeed]     = useState(0);
  const [nBytes, setNBytes] = useState(64);
  const { loading, data, error, run } = useAsync(api.prgFromPrf);

  const submit = () => run({ key_hex: keyHex, seed_int: Number(seed), n_bytes: Number(nBytes) });

  return (
    <PanelCard
      title="PRG from PRF"
      formula={"G_k(s)=F_k(s\\,\\|\\,0)\\,\\|\\,F_k(s\\,\\|\\,1)"}
      desc="Reduction: any secure PRF induces a secure PRG. Output verified with NIST tests."
      inputContent={
        <>
          <Field label="Key k" hint="16 bytes = 32 hex chars">
            <input value={keyHex} onChange={e => setKeyHex(e.target.value)} className="input mono" />
          </Field>
          <Field label="Seed s">
            <input type="number" value={seed} onChange={e => setSeed(e.target.value)} className="input" style={{ width: "110px" }} />
          </Field>
          <Field label="Output bytes" hint="1 – 4096">
            <input type="number" value={nBytes} min={1} max={4096} onChange={e => setNBytes(e.target.value)} className="input" style={{ width: "110px" }} />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Generating…</> : "Generate"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <PRGFromPRFResult data={data} />}
        </ResultArea>
      }
    />
  );
}

// ─── Distinguishing Game Panel ────────────────────────────────────────────────
export function DistGamePanel() {
  const [nQ, setNQ]         = useState(100);
  const [inBits, setInBits] = useState(8);
  const { loading, data, error, run } = useAsync(api.distinguishGame);

  const submit = () => run({ n_queries: Number(nQ), input_bits: Number(inBits) });

  return (
    <PanelCard
      title="PRF Distinguishing Game"
      formula={"\\left|\\Pr[\\mathcal{A}^{F_k}=1]-\\Pr[\\mathcal{A}^{R}=1]\\right| \\leq \\mathrm{negl}(n)"}
      desc="Queries real PRF vs random oracle. Distance < 0.15 confirms the PRF is secure."
      inputContent={
        <>
          <Field label="Oracle queries" hint="Adversary calls to F_k and R (1–1000)">
            <input type="number" value={nQ} min={1} max={1000} onChange={e => setNQ(e.target.value)} className="input" style={{ width: "110px" }} />
          </Field>
          <Field label="Input bit-width" hint={<>Domain size = <Math expr="2^n" /></>}>
            <input type="number" value={inBits} min={1} max={32} onChange={e => setInBits(e.target.value)} className="input" style={{ width: "80px" }} />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Running game…</> : "Run Game"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <DistGameResult data={data} />}
        </ResultArea>
      }
    />
  );
}

// ─── GGM Tree — client-side AES-based computation (no backend needed) ────────

function hexToBytes(hex) {
  const clean = hex.replace(/[^0-9a-fA-F]/g, "").slice(0, 32).padEnd(32, "0");
  const arr = new Uint8Array(16);
  for (let i = 0; i < 16; i++) arr[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
  return arr;
}

function bytesToHex(arr) {
  return Array.from(arr).map(b => b.toString(16).padStart(2, "0")).join("");
}

// G(k) = (AES_k(0...0), AES_k(0...1))  — length-doubling PRG via AES-CBC
async function doublingPRG(nodeKey) {
  const rawKey = nodeKey instanceof Uint8Array ? nodeKey : new Uint8Array(nodeKey);
  const cryptoKey = await crypto.subtle.importKey("raw", rawKey, { name: "AES-CBC" }, false, ["encrypt"]);
  const iv = new Uint8Array(16); // zero IV → AES-CBC block 0 = AES-ECB(key, plaintext)
  const pt0 = new Uint8Array(16);          // 0x00 * 16  → left child
  const pt1 = new Uint8Array(16); pt1[15] = 1; // 0x00…01 → right child
  const [buf0, buf1] = await Promise.all([
    crypto.subtle.encrypt({ name: "AES-CBC", iv }, cryptoKey, pt0),
    crypto.subtle.encrypt({ name: "AES-CBC", iv }, cryptoKey, pt1),
  ]);
  return [new Uint8Array(buf0).slice(0, 16), new Uint8Array(buf1).slice(0, 16)];
}

async function computeGGMTree(keyHex, xBinary, inputBits) {
  const keyBytes = hexToBytes(keyHex);
  const bits = xBinary.split("").map(Number);
  const levels = [];
  let current = keyBytes;

  levels.push({ level: 0, is_root: true, full_hex: bytesToHex(current) });

  for (let i = 0; i < inputBits; i++) {
    const [left, right] = await doublingPRG(current);
    const bit = bits[i];
    const pathChild = bit === 1 ? right : left;
    const sibling   = bit === 1 ? left  : right;
    levels.push({
      level: i + 1,
      path_bit: bit,
      path_full_hex:    bytesToHex(pathChild),
      sibling_full_hex: bytesToHex(sibling),
      is_leaf: i === inputBits - 1,
    });
    current = pathChild;
  }

  return {
    key_hex:    bytesToHex(keyBytes),
    input:      parseInt(xBinary, 2),
    input_bits: inputBits,
    x_binary:   xBinary,
    levels,
    output_hex: bytesToHex(current),
  };
}

// ─── Tree renderer ───────────────────────────────────────────────────────────
function hx(h, n = 16) { return h ? h.slice(0, n) + "…" : "??"; }

function GGMTreeViz({ data }) {
  if (!data || !data.levels) return null;
  const { levels, x_binary, output_hex, input } = data;

  return (
    <div className="ggm-viz">
      {/* Query row */}
      <div className="ggm-query-row">
        <span className="ggm-query-label">Query x =</span>
        <div className="ggm-query-bits">
          {x_binary.split("").map((b, i) => (
            <span key={i} className={`ggm-qbit${b === "1" ? " ggm-qbit-one" : ""}`}>
              b<sub>{i + 1}</sub>={b}
            </span>
          ))}
        </div>
        <span className="ggm-query-dec">= {input}</span>
      </div>

      {/* Root node */}
      <div className="ggm-level-row">
        <div className="ggm-root-node">
          <div className="ggm-node-badge ggm-badge-root">ROOT KEY  k</div>
          <div className="ggm-node-hex">{hx(levels[0].full_hex)}</div>
          <div className="ggm-node-hint">G(k) → (G₀, G₁)</div>
        </div>
      </div>

      {/* Per-level pairs */}
      {levels.slice(1).map((lvl, i) => {
        const leftPath  = lvl.path_bit === 0;
        const leftHex   = leftPath ? lvl.path_full_hex  : lvl.sibling_full_hex;
        const rightHex  = leftPath ? lvl.sibling_full_hex : lvl.path_full_hex;
        const isLeaf    = lvl.is_leaf;

        return (
          <div key={i} className="ggm-level-group">
            <svg className="ggm-svg-connector" viewBox="0 0 260 36" preserveAspectRatio="none">
              <path d="M130,0 C130,18 60,18 60,36"
                stroke={leftPath  ? "#4f46e5" : "#cbd5e1"}
                strokeWidth={leftPath  ? "3" : "1.5"} fill="none" strokeLinecap="round"/>
              <path d="M130,0 C130,18 200,18 200,36"
                stroke={!leftPath ? "#4f46e5" : "#cbd5e1"}
                strokeWidth={!leftPath ? "3" : "1.5"} fill="none" strokeLinecap="round"/>
            </svg>

            <div className="ggm-pair-row">
              <div className={`ggm-tree-node${leftPath ? " ggm-node-active" : " ggm-node-pruned"}${isLeaf && leftPath ? " ggm-node-leaf" : ""}`}>
                <div className={`ggm-node-badge${leftPath ? " ggm-badge-active" : " ggm-badge-pruned"}`}>
                  {leftPath ? `b${i+1}=0  ✓ PATH` : `b${i+1}=0  pruned`}
                </div>
                <div className="ggm-node-name">G₀</div>
                <div className="ggm-node-hex">{hx(leftHex)}</div>
                {isLeaf && leftPath && <div className="ggm-leaf-tag">F_k(x)  leaf</div>}
              </div>

              <div className={`ggm-tree-node${!leftPath ? " ggm-node-active" : " ggm-node-pruned"}${isLeaf && !leftPath ? " ggm-node-leaf" : ""}`}>
                <div className={`ggm-node-badge${!leftPath ? " ggm-badge-active" : " ggm-badge-pruned"}`}>
                  {!leftPath ? `b${i+1}=1  ✓ PATH` : `b${i+1}=1  pruned`}
                </div>
                <div className="ggm-node-name">G₁</div>
                <div className="ggm-node-hex">{hx(rightHex)}</div>
                {isLeaf && !leftPath && <div className="ggm-leaf-tag">F_k(x)  leaf</div>}
              </div>
            </div>
          </div>
        );
      })}

      {/* Output card */}
      <div className="ggm-output-card">
        <div className="ggm-output-top">
          F<sub style={{ fontSize: "0.7em" }}>k</sub>({x_binary}) =
        </div>
        <div className="ggm-output-hex">{output_hex}</div>
        <div className="ggm-output-hint">AES-based PRG · {x_binary.length}-step path · leaf node value</div>
      </div>
    </div>
  );
}

// ─── Panel ────────────────────────────────────────────────────────────────────
export function GGMTreePanel() {
  const [keyHex,    setKeyHex]    = useState("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
  const [xBinary,   setXBinary]   = useState("0101");
  const [inputBits, setInputBits] = useState(4);
  const [data,      setData]      = useState(null);
  const [loading,   setLoading]   = useState(false);
  const [error,     setError]     = useState(null);

  const xPadded = xBinary.padEnd(inputBits, "0").slice(0, inputBits);

  // Recompute on any change — pure client-side AES, no backend call
  useEffect(() => {
    let cancelled = false;
    const timer = setTimeout(async () => {
      if (!cancelled) {
        setLoading(true);
        setError(null);
      }
      try {
        const result = await computeGGMTree(keyHex, xPadded, inputBits);
        if (!cancelled) { setData(result); setLoading(false); }
      } catch (e) {
        if (!cancelled) { setError(e.message); setLoading(false); }
      }
    }, 250);
    return () => { cancelled = true; clearTimeout(timer); };
  }, [keyHex, xPadded, inputBits]);

  const handleBitClick = (i) => {
    const bits = xPadded.split("");
    bits[i] = bits[i] === "0" ? "1" : "0";
    setXBinary(bits.join(""));
  };

  const handleDepthChange = (n) => {
    setInputBits(n);
    setXBinary(xBinary.padEnd(n, "0").slice(0, n));
  };

  return (
    <PanelCard
      title="GGM Tree Visualiser"
      formula={"F_k(b_1 \\cdots b_n) = G_{b_n}(\\cdots G_{b_1}(k) \\cdots)"}
      desc="Each node splits via G(v)=(v₀,v₁). Path b₁⋯bₙ picks left (0) or right (1) at each level. Blue = active path; grey = pruned. Click any bit to toggle — the path re-routes instantly. Computed entirely in-browser via AES."
      inputContent={
        <>
          <Field label="Key k" hint="16 bytes · 32 hex characters">
            <input
              value={keyHex}
              onChange={e => setKeyHex(e.target.value)}
              className="input mono"
              placeholder="32 hex chars…"
            />
          </Field>

          <Field label={`Tree depth  n = ${inputBits}`} hint="1 – 8 levels">
            <input
              type="range" value={inputBits} min={1} max={8} step={1}
              onChange={e => handleDepthChange(Number(e.target.value))}
              className="range-slider" style={{ width: "100%" }}
            />
            <span className="range-value-label">
              {inputBits} levels → 2<sup>{inputBits}</sup> = {1 << inputBits} possible leaves
            </span>
          </Field>

          <Field label="Query x — click bits to toggle">
            <div className="ggm-toggle-row">
              {xPadded.split("").map((b, i) => (
                <button
                  key={i}
                  className={`ggm-toggle-bit${b === "1" ? " ggm-tb-one" : " ggm-tb-zero"}`}
                  onClick={() => handleBitClick(i)}
                  title={`b${i + 1} = ${b} — click to flip`}
                >
                  <span className="ggm-tb-index">b{i + 1}</span>
                  <span className="ggm-tb-val">{b}</span>
                </button>
              ))}
            </div>
            <div className="ggm-x-summary">
              <span className="mono">{xPadded}</span>
              <span style={{ color: "var(--text-4)" }}>₂</span>
              <span style={{ margin: "0 6px", color: "var(--text-4)" }}>=</span>
              <span className="mono" style={{ color: "var(--indigo-600)" }}>{parseInt(xPadded, 2)}</span>
              <span style={{ marginLeft: 4, color: "var(--text-4)" }}>₁₀</span>
            </div>
          </Field>

          {loading && <div className="ggm-status-loading"><Spinner /> Computing…</div>}
          {error   && <div className="result-area result-error" style={{ marginTop: 8 }}><span className="result-error-label">Error</span><pre>{error}</pre></div>}
        </>
      }
      outputContent={
        <div className="ggm-output-area">
          {loading && !data && <div className="ggm-empty-state"><Spinner /> Building tree…</div>}
          {data && <GGMTreeViz data={data} />}
        </div>
      }
    />
  );
}

// ═══════════════════════════════════════════════════════════════
// PA#3 PANELS
// ═══════════════════════════════════════════════════════════════

export function PA3EncryptPanel() {
  const [scheme, setScheme] = useState("secure");
  const [keyHex, setKeyHex] = useState("00112233445566778899aabbccddeeff");
  const [message, setMessage] = useState("PA3 secure encryption demo");
  const { loading, data, error, run } = useAsync(api.pa3Encrypt);

  const submit = () => run({ scheme, key_hex: keyHex, message });

  return (
    <PanelCard
      title="Encrypt"
      formula={"\\mathrm{Enc}_k(m) = r \\| (m \\oplus G_k(r))"}
      desc="The secure scheme uses a fresh random nonce. The broken scheme reuses its nonce and loses CPA security."
      inputContent={
        <>
          <Field label="Scheme">
            <SegControl value={scheme} onChange={setScheme} options={[
              { value: "secure", label: "Secure" },
              { value: "broken", label: "Broken" },
            ]} />
          </Field>
          <Field label="Key k" hint="16 bytes = 32 hex chars">
            <input value={keyHex} onChange={e => setKeyHex(e.target.value)} className="input mono" />
          </Field>
          <Field label="Message">
            <input value={message} onChange={e => setMessage(e.target.value)} className="input" />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Encrypting…</> : "Encrypt"}
          </button>
        </>
      }
      outputContent={<ResultArea loading={loading} error={error} data={data} />}
    />
  );
}

export function PA3DecryptPanel() {
  const [scheme, setScheme] = useState("secure");
  const [keyHex, setKeyHex] = useState("00112233445566778899aabbccddeeff");
  const [ciphertextHex, setCiphertextHex] = useState("");
  const { loading, data, error, run } = useAsync(api.pa3Decrypt);

  const submit = () => run({ scheme, key_hex: keyHex, ciphertext_hex: ciphertextHex });

  return (
    <PanelCard
      title="Decrypt"
      formula={"\\mathrm{Dec}_k(r \\| c) = c \\oplus G_k(r)"}
      desc="Paste a ciphertext from the Encrypt tab to recover the original plaintext."
      inputContent={
        <>
          <Field label="Scheme">
            <SegControl value={scheme} onChange={setScheme} options={[
              { value: "secure", label: "Secure" },
              { value: "broken", label: "Broken" },
            ]} />
          </Field>
          <Field label="Key k" hint="16 bytes = 32 hex chars">
            <input value={keyHex} onChange={e => setKeyHex(e.target.value)} className="input mono" />
          </Field>
          <Field label="Ciphertext (hex)">
            <textarea value={ciphertextHex} onChange={e => setCiphertextHex(e.target.value)} className="input mono" rows={5} />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Decrypting…</> : "Decrypt"}
          </button>
        </>
      }
      outputContent={<ResultArea loading={loading} error={error} data={data} />}
    />
  );
}

export function PA3CPAGamePanel() {
  const [scheme, setScheme] = useState("secure");
  const [trials, setTrials] = useState(200);
  const { loading, data, error, run } = useAsync(api.pa3CpaGame);

  const submit = () => run({ scheme, trials: Number(trials) });

  return (
    <PanelCard
      title="CPA Game"
      formula={"\\mathrm{Adv}^{\\text{ind-cpa}}_{\\mathcal{A}} = \\left|\\Pr[\\mathcal{A}\\text{ wins}] - \\tfrac{1}{2}\\right|"}
      desc="The secure scheme should stay near random guessing, while the broken deterministic scheme should be easy to distinguish."
      inputContent={
        <>
          <Field label="Scheme">
            <SegControl value={scheme} onChange={setScheme} options={[
              { value: "secure", label: "Secure" },
              { value: "broken", label: "Broken" },
            ]} />
          </Field>
          <Field label="Trials">
            <input type="number" value={trials} min={10} max={5000} onChange={e => setTrials(e.target.value)} className="input" style={{ width: "120px" }} />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Running…</> : "Run CPA Game"}
          </button>
        </>
      }
      outputContent={<ResultArea loading={loading} error={error} data={data} />}
    />
  );
}

export function PRPPanel() {
  const [keyHex, setKeyHex] = useState("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
  const [ptHex, setPtHex]   = useState("00112233445566778899aabbccddeeff");
  const [dir, setDir]       = useState("forward");
  const { loading, data, error, run } = useAsync(api.prp);
  const submit = () => run({ key_hex: keyHex, plaintext_hex: ptHex, direction: dir });
  const formula = dir === "forward" ? "F_k(x) = \\text{AES}_k(x)" : "F_k^{-1}(y) = \\text{AES}_k^{-1}(y)";
  return (
    <PanelCard
      title="Pseudorandom Permutation"
      formula={formula}
      desc="AES-128 is a PRP: a keyed bijection indistinguishable from a random permutation. Verifies F_k^{-1}(F_k(x)) = x and shows the PRP–PRF switching lemma bound."
      inputContent={
        <>
          <Field label="Direction">
            <SegControl value={dir} onChange={setDir} options={[
              { value: "forward", label: "Encrypt F_k(x)" },
              { value: "inverse", label: "Decrypt F_k⁻¹(y)" },
            ]} />
          </Field>
          <Field label="Key k" hint="16 bytes = 32 hex chars">
            <input value={keyHex} onChange={e => setKeyHex(e.target.value)} className="input mono" />
          </Field>
          <Field label="Input (16 bytes hex)">
            <input value={ptHex} onChange={e => setPtHex(e.target.value)} className="input mono" />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Computing…</> : "Evaluate PRP"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <PRPResult data={data} />}
        </ResultArea>
      }
    />
  );
}

export function ECBPanel() {
  const [keyHex, setKeyHex]     = useState("2b7e151628aed2a6abf7158809cf4f3c");
  const [plaintext, setPlaintext] = useState("YELLOW SUBMARINEYELLOW SUBMARINESECRET DATA!!!!!");
  const { loading, data, error, run } = useAsync(api.aesModes);
  const submit = () => run({ mode: "ecb", key_hex: keyHex, plaintext });
  return (
    <PanelCard
      title="ECB Mode — Electronic Codebook"
      formula={"c_i = \\text{AES}_k(m_i)"}
      desc="INSECURE: identical plaintext blocks → identical ciphertext blocks. Not CPA-secure. The pattern demo below shows the vulnerability directly."
      inputContent={
        <>
          <Field label="Key k" hint="16 bytes = 32 hex chars">
            <input value={keyHex} onChange={e => setKeyHex(e.target.value)} className="input mono" />
          </Field>
          <Field label="Plaintext" hint="Try two identical 16-byte blocks to see the pattern leak">
            <input value={plaintext} onChange={e => setPlaintext(e.target.value)} className="input" />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Encrypting…</> : "Encrypt ECB"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <ModesResult data={data} />}
        </ResultArea>
      }
    />
  );
}

export function CBCPanel() {
  const [keyHex, setKeyHex]     = useState("2b7e151628aed2a6abf7158809cf4f3c");
  const [plaintext, setPlaintext] = useState("Hello, CBC World! This is secure.");
  const [ivHex, setIvHex]       = useState("");
  const { loading, data, error, run } = useAsync(api.aesModes);
  const submit = () => run({ mode: "cbc", key_hex: keyHex, plaintext, iv_hex: ivHex || undefined });
  return (
    <PanelCard
      title="CBC Mode — Cipher Block Chaining"
      formula={"c_i = \\text{AES}_k(m_i \\oplus c_{i-1}),\\quad c_0 = IV"}
      desc="CPA-secure with a random IV. Each ciphertext block depends on all previous blocks. Sequential encryption, but parallel decryption."
      inputContent={
        <>
          <Field label="Key k" hint="16 bytes = 32 hex chars">
            <input value={keyHex} onChange={e => setKeyHex(e.target.value)} className="input mono" />
          </Field>
          <Field label="Plaintext">
            <input value={plaintext} onChange={e => setPlaintext(e.target.value)} className="input" />
          </Field>
          <Field label="IV (hex)" hint="Leave empty for a fresh random IV">
            <input value={ivHex} onChange={e => setIvHex(e.target.value)} className="input mono" placeholder="random" />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Encrypting…</> : "Encrypt CBC"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <ModesResult data={data} />}
        </ResultArea>
      }
    />
  );
}

export function CTRPanel() {
  const [keyHex, setKeyHex]     = useState("2b7e151628aed2a6abf7158809cf4f3c");
  const [plaintext, setPlaintext] = useState("Hello, CTR mode! Fully parallelizable.");
  const { loading, data, error, run } = useAsync(api.aesModes);
  const submit = () => run({ mode: "ctr", key_hex: keyHex, plaintext });
  return (
    <PanelCard
      title="CTR Mode — Counter Mode"
      formula={"c_i = m_i \\oplus \\text{AES}_k(\\text{nonce} \\| i)"}
      desc="CPA-secure, fully parallelizable, turns AES into a stream cipher. No padding required. Nonce must never repeat with the same key."
      inputContent={
        <>
          <Field label="Key k" hint="16 bytes = 32 hex chars">
            <input value={keyHex} onChange={e => setKeyHex(e.target.value)} className="input mono" />
          </Field>
          <Field label="Plaintext">
            <input value={plaintext} onChange={e => setPlaintext(e.target.value)} className="input" />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Encrypting…</> : "Encrypt CTR"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <ModesResult data={data} />}
        </ResultArea>
      }
    />
  );
}

export function PaddingOraclePanel() {
  const [plaintext, setPlaintext] = useState("Secret message!!");
  const { loading, data, error, run } = useAsync(api.paddingOracle);
  const submit = () => run({ plaintext });
  return (
    <PanelCard
      title="Padding Oracle Attack on CBC"
      formula={"m_i = D_k(c_i) \\oplus c_{i-1}"}
      desc="If a server leaks valid/invalid PKCS#7 padding, an attacker recovers each byte with ≤ 256 oracle queries. CBC is CPA-secure but NOT CCA-secure."
      fullWidth
      inputContent={
        <>
          <Field label="Plaintext to encrypt then attack" hint="16 bytes used">
            <input value={plaintext} onChange={e => setPlaintext(e.target.value)} className="input" />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Attacking…</> : "Run Padding Oracle Attack"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <PaddingOracleResult data={data} />}
        </ResultArea>
      }
    />
  );
}

// ═══════════════════════════════════════════════════════════════
// PA#4 PANELS
// ═══════════════════════════════════════════════════════════════

export function MACPanel() {
  const [mode, setMode]       = useState("cbc");
  const [keyHex, setKeyHex]   = useState("0f1e2d3c4b5a69788796a5b4c3d2e1f0");
  const [message, setMessage] = useState("Authenticate this message");
  const [tagHex, setTagHex]   = useState("");
  const { loading, data, error, run } = useAsync(api.mac);
  const submit = () => run({ mac_mode: mode, key_hex: keyHex, message, tag_hex: tagHex || undefined });
  const formula = mode === "prf"
    ? "\\text{Mac}_k(m) = F_k(m)"
    : "T_i = \\text{AES}_k(m_i \\oplus T_{i-1})";
  return (
    <PanelCard
      title="Message Authentication Code"
      formula={formula}
      desc="MAC provides integrity + authenticity. PA5 focuses on PRF-MAC for fixed-length messages and CBC-MAC for variable-length messages. HMAC appears separately in PA10."
      inputContent={
        <>
          <Field label="MAC Scheme">
            <SegControl value={mode} onChange={setMode} options={[
              { value: "cbc",  label: "CBC-MAC" },
              { value: "prf",  label: "PRF-MAC" },
            ]} />
          </Field>
          <Field label="Key k" hint="16 bytes = 32 hex chars">
            <input value={keyHex} onChange={e => setKeyHex(e.target.value)} className="input mono" />
          </Field>
          <Field label="Message">
            <input value={message} onChange={e => setMessage(e.target.value)} className="input" />
          </Field>
          <Field label="Tag to verify (hex)" hint="Optional — leave empty to just compute">
            <input value={tagHex} onChange={e => setTagHex(e.target.value)} className="input mono" placeholder="optional" />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Computing…</> : "Compute MAC"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <MACResult data={data} />}
        </ResultArea>
      }
    />
  );
}

export function LengthExtPanel() {
  const [message, setMessage] = useState("user=alice&role=user");
  const { loading, data, error, run } = useAsync(api.lengthExtension);
  const submit = () => run({ message });
  return (
    <PanelCard
      title="Length-Extension Attack"
      formula={"H(k \\| m \\| \\text{pad} \\| m') = \\text{Extend}(H(k \\| m),\\, m')"}
      desc="Naive MAC = H(k‖m) is vulnerable: the attacker extends the hash without knowing k. HMAC wraps with two key-padded layers to prevent this."
      fullWidth
      inputContent={
        <>
          <Field label="Original message" hint="Attacker knows this and its tag">
            <input value={message} onChange={e => setMessage(e.target.value)} className="input" />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Attacking…</> : "Run Length-Extension Attack"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <LengthExtResult data={data} />}
        </ResultArea>
      }
    />
  );
}

export function EUFCMAPanel() {
  const [mode, setMode] = useState("cbc");
  const [nQ, setNQ]     = useState(10);
  const { loading, data, error, run } = useAsync(api.eufCma);
  const submit = () => run({ mac_mode: mode, n_queries: Number(nQ) });
  return (
    <PanelCard
      title="EUF-CMA Security Game"
      formula={"\\Pr[\\text{Forge}] \\leq \\frac{q}{2^n}"}
      desc="Existential Unforgeability under Chosen Message Attack. Adversary makes q adaptive tag queries then tries to forge on a new message. Probability is negligible for n=128."
      inputContent={
        <>
          <Field label="MAC Scheme">
            <SegControl value={mode} onChange={setMode} options={[
              { value: "cbc",  label: "CBC-MAC" },
              { value: "prf",  label: "PRF-MAC" },
            ]} />
          </Field>
          <Field label="Oracle queries" hint="1 – 50">
            <input type="number" value={nQ} min={1} max={50} onChange={e => setNQ(e.target.value)} className="input" style={{ width: "100px" }} />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Running game…</> : "Run EUF-CMA Game"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <EUFCMAResult data={data} />}
        </ResultArea>
      }
    />
  );
}

// ═══════════════════════════════════════════════════════════════
// PA#5 PANELS
// ═══════════════════════════════════════════════════════════════

export function RSAPanel() {
  const [bits, setBits]       = useState(512);
  const [keys, setKeys]       = useState(null);
  const [message, setMessage] = useState("Hello RSA!");
  const [cipherInt, setCipherInt] = useState(null);

  const keygen = useAsync(api.rsaKeygen);
  const encrypt = useAsync(api.rsaEncrypt);
  const decrypt = useAsync(api.rsaDecrypt);

  const genKeys = async () => {
    const res = await api.rsaKeygen({ bits: Number(bits) });
    setKeys(res);
    keygen.run({ bits: Number(bits) });
  };

  const doEncrypt = async () => {
    if (!keys) return;
    const res = await api.rsaEncrypt({ n_hex: keys.n_hex, e: keys.e, message });
    encrypt.run({ n_hex: keys.n_hex, e: keys.e, message });
    setCipherInt(res.ciphertext_int);
  };

  const doDecrypt = () => {
    if (!keys || cipherInt === null) return;
    decrypt.run({ n_hex: keys.n_hex, d_hex: keys.d_hex, ciphertext_int: cipherInt });
  };

  return (
    <PanelCard
      title="RSA Encryption"
      formula={"c = m^e \\bmod n, \\quad m = c^d \\bmod n"}
      desc="Generate keys, encrypt a message, then decrypt it. Security rests on the hardness of factoring n = p*q."
      fullWidth
      inputContent={
        <>
          <Field label="Key size (bits)" hint="128–2048 (512 default for demo speed)">
            <input type="number" value={bits} min={128} max={2048} onChange={e => setBits(e.target.value)} className="input" style={{ width: "100px" }} />
          </Field>
          <button className="btn-primary" onClick={genKeys} disabled={keygen.loading}>
            {keygen.loading ? <><Spinner /> Generating…</> : "1. Generate RSA Keys"}
          </button>
          {keys && (
            <>
              <Field label="Message to encrypt">
                <input value={message} onChange={e => setMessage(e.target.value)} className="input" />
              </Field>
              <div style={{ display: "flex", gap: 8 }}>
                <button className="btn-primary" onClick={doEncrypt} disabled={encrypt.loading}>
                  {encrypt.loading ? <><Spinner /> Encrypting…</> : "2. Encrypt"}
                </button>
                <button className="btn-primary" onClick={doDecrypt} disabled={decrypt.loading || cipherInt === null}>
                  {decrypt.loading ? <><Spinner /> Decrypting…</> : "3. Decrypt"}
                </button>
              </div>
            </>
          )}
        </>
      }
      outputContent={
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <ResultArea loading={keygen.loading} error={keygen.error} data={keygen.data}>
            {keygen.data && <RSAKeygenResult data={keygen.data} />}
          </ResultArea>
          {encrypt.data && (
            <ResultArea loading={false} error={encrypt.error} data={encrypt.data}>
              <RSACryptResult data={encrypt.data} />
            </ResultArea>
          )}
          {decrypt.data && (
            <ResultArea loading={false} error={decrypt.error} data={decrypt.data}>
              <RSACryptResult data={decrypt.data} />
            </ResultArea>
          )}
        </div>
      }
    />
  );
}

export function RSASignPanel() {
  const [keys, setKeys]       = useState(null);
  const [message, setMessage] = useState("Sign this");
  const keygen = useAsync(api.rsaKeygen);
  const sign = useAsync(api.rsaSign);

  const genKeys = async () => {
    const res = await api.rsaKeygen({ bits: 512 });
    setKeys(res);
    keygen.run({ bits: 512 });
  };

  const doSign = () => {
    if (!keys) return;
    sign.run({ n_hex: keys.n_hex, e: keys.e, d_hex: keys.d_hex, message });
  };

  return (
    <PanelCard
      title="RSA Signatures"
      formula={"\\sigma = m^d \\bmod n, \\quad \\text{Verify: } m = \\sigma^e \\bmod n"}
      desc="Sign a message with the private key, verify with the public key. Provides non-repudiation."
      inputContent={
        <>
          <button className="btn-primary" onClick={genKeys} disabled={keygen.loading}>
            {keygen.loading ? <><Spinner /> Generating…</> : "1. Generate Keys"}
          </button>
          {keys && (
            <>
              <Field label="Message to sign">
                <input value={message} onChange={e => setMessage(e.target.value)} className="input" />
              </Field>
              <button className="btn-primary" onClick={doSign} disabled={sign.loading}>
                {sign.loading ? <><Spinner /> Signing…</> : "2. Sign + Verify"}
              </button>
            </>
          )}
        </>
      }
      outputContent={
        <div style={{ display: "flex", flexDirection: "column", gap: 12 }}>
          <ResultArea loading={keygen.loading} error={keygen.error} data={keygen.data}>
            {keygen.data && <RSAKeygenResult data={keygen.data} />}
          </ResultArea>
          {sign.data && (
            <ResultArea loading={false} error={sign.error} data={sign.data}>
              <RSASignResult data={sign.data} />
            </ResultArea>
          )}
        </div>
      }
    />
  );
}

export function RSACPAPanel() {
  const [bits, setBits] = useState(256);
  const { loading, data, error, run } = useAsync(api.rsaCpaDemo);
  const submit = () => run({ bits: Number(bits) });
  return (
    <PanelCard
      title="Textbook RSA: NOT CPA-Secure"
      formula={"\\text{Enc}(m) = m^e \\bmod n \\quad \\text{(deterministic!)}"}
      desc="Textbook RSA encrypts the same message to the same ciphertext every time. An IND-CPA adversary wins with probability 1."
      inputContent={
        <>
          <Field label="RSA key size" hint="Smaller = faster demo">
            <input type="number" value={bits} min={128} max={1024} onChange={e => setBits(e.target.value)} className="input" style={{ width: "100px" }} />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Running…</> : "Run CPA Demo"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <RSACPAResult data={data} />}
        </ResultArea>
      }
    />
  );
}

export function DHPanel() {
  const { loading, data, error, run } = useAsync(api.dhExchange);
  return (
    <PanelCard
      title="Diffie-Hellman Key Exchange"
      formula={"K = g^{ab} \\bmod p"}
      desc="Alice and Bob each pick a secret exponent. They exchange public values g^a and g^b, and independently compute the shared secret g^{ab} mod p."
      inputContent={
        <>
          <p style={{ fontSize: 13, color: "var(--text-3)", margin: "0 0 8px" }}>
            Uses a 1536-bit safe prime (Oakley Group 1, RFC 2409). Press Run to execute a full exchange.
          </p>
          <button className="btn-primary" onClick={() => run({})} disabled={loading}>
            {loading ? <><Spinner /> Exchanging…</> : "Run DH Exchange"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <DHExchangeResult data={data} />}
        </ResultArea>
      }
    />
  );
}

export function MITMPanel() {
  const { loading, data, error, run } = useAsync(api.dhMitm);
  return (
    <PanelCard
      title="Man-in-the-Middle Attack"
      formula={"K_{AM} \\neq K_{AB}"}
      desc="Without authentication, Mallory intercepts the exchange. She establishes separate shared keys with Alice and Bob, reading and modifying all traffic."
      fullWidth
      inputContent={
        <>
          <button className="btn-primary" onClick={() => run({})} disabled={loading}>
            {loading ? <><Spinner /> Attacking…</> : "Run MITM Attack"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <MITMResult data={data} />}
        </ResultArea>
      }
    />
  );
}

export function AuthDHPanel() {
  const [bits, setBits] = useState(512);
  const { loading, data, error, run } = useAsync(api.authenticatedDh);
  const submit = () => run({ rsa_bits: Number(bits) });
  return (
    <PanelCard
      title="Authenticated Diffie-Hellman"
      formula={"\\text{Sign}_{sk_A}(g^a) \\Rightarrow \\text{Verify}_{pk_A}"}
      desc="Alice signs her DH public key with RSA. Bob verifies the signature before computing the shared secret. This prevents the MITM attack."
      inputContent={
        <>
          <Field label="RSA key size for signatures">
            <input type="number" value={bits} min={256} max={2048} onChange={e => setBits(e.target.value)} className="input" style={{ width: "100px" }} />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Running…</> : "Run Authenticated DH"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <AuthDHResult data={data} />}
        </ResultArea>
      }
    />
  );
}

export function PA7HashPanel() {
  const [message, setMessage] = useState("hello merkle-damgard");
  const [blockSize, setBlockSize] = useState(8);
  const [outputSize, setOutputSize] = useState(4);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);
  const [editableBlocks, setEditableBlocks] = useState([]);
  const [editedIndex, setEditedIndex] = useState(null);
  const replayTimerRef = useRef(null);

  const submit = async () => {
    setLoading(true);
    setError(null);
    try {
      const result = await api.pa7Hash({
        message,
        block_size: Number(blockSize),
        output_size: Number(outputSize),
      });
      setData(result);
      setEditableBlocks(result.blocks_hex ?? []);
      setEditedIndex(null);
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    return () => {
      if (replayTimerRef.current) {
        clearTimeout(replayTimerRef.current);
      }
    };
  }, []);

  const updateBlock = (index, value) => {
    const normalized = value.toLowerCase().replace(/[^0-9a-f]/g, "");
    setEditableBlocks(prev => prev.map((block, i) => (i === index ? normalized : block)));
    setEditedIndex(index);
  };

  useEffect(() => {
    if (!data || editedIndex === null) {
      return;
    }
    const expectedHexLen = Number(blockSize) * 2;
    if (editableBlocks.length === 0 || editableBlocks.some(block => block.length !== expectedHexLen)) {
      return;
    }
    if (replayTimerRef.current) {
      clearTimeout(replayTimerRef.current);
    }
    replayTimerRef.current = setTimeout(async () => {
      setLoading(true);
      setError(null);
      try {
        const result = await api.pa7HashBlocks({
          blocks_hex: editableBlocks,
          iv_hex: data.iv_hex,
          block_size: Number(blockSize),
          output_size: Number(outputSize),
        });
        setData(prev => ({
          ...(prev ?? {}),
          ...result,
          replay_mode: true,
          edited_from_block: editedIndex + 1,
          message_text: prev?.message_text,
          message_hex: prev?.message_hex,
          message_length_bytes: prev?.message_length_bytes,
          message_length_bits: prev?.message_length_bits,
          padded_hex: editableBlocks.join(""),
        }));
      } catch (e) {
        setError(e.message);
      } finally {
        setLoading(false);
      }
    }, 280);
  }, [editableBlocks, editedIndex, blockSize, outputSize, data]);

  const expectedHexLen = Number(blockSize) * 2;

  return (
    <PanelCard
      title="Merkle-Damgard Chain Viewer"
      formula={"z_i = h(z_{i-1} \\Vert M_i)"}
      desc="The toy PA7 compression function xors the chaining value with each equal-sized chunk inside the current block. This viewer shows the chain as visual boxes, and editing any padded block recomputes the chain from that block onward."
      fullWidth
      inputContent={
        <>
          <Field label="Message" hint="Type a message, build its padded blocks, then edit any block below to replay the chain.">
            <input value={message} onChange={e => setMessage(e.target.value)} className="input" />
          </Field>
          <Field label="Block size (bytes)" hint="Toy demo default: 8">
            <input type="number" value={blockSize} min={2} max={64} onChange={e => setBlockSize(e.target.value)} className="input" style={{ width: "100px" }} />
          </Field>
          <Field label="Digest size (bytes)" hint="Toy demo default: 4">
            <input type="number" value={outputSize} min={1} max={32} onChange={e => setOutputSize(e.target.value)} className="input" style={{ width: "100px" }} />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Hashing…</> : "Run PA7 Hash"}
          </button>
          {data && (
            <div className="pa7-edit-help">
              <Badge variant="info">Interactive</Badge>
              <span>Each block below is editable hex. Valid length: {expectedHexLen} hex chars.</span>
            </div>
          )}
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && (
            <div className="result-structured pa7-result-wrap">
              <div className="result-row pa7-summary-row">
                <Badge variant="info">Toy XOR Compression</Badge>
                <span className="result-label">{data.message_length_bytes ?? 0} bytes {"->"} {data.blocks_hex?.length} blocks</span>
                {data.replay_mode && <Badge variant="pass">Recomputed From Block {data.edited_from_block}</Badge>}
              </div>
              <div className="result-field">
                <span className="result-field-label">Digest</span>
                <code className="hex-output">{data.digest_hex}</code>
              </div>
              <div className="result-field">
                <span className="result-field-label">Padded message</span>
                <code className="hex-output">{data.padded_hex}</code>
              </div>
              <div className="pa7-chain-board">
                <div className="pa7-state-node pa7-state-root">
                  <span className="pa7-node-kicker">Initial state</span>
                  <span className="pa7-node-title">z₀ = IV</span>
                  <code className="pa7-node-hex">{data.iv_hex}</code>
                </div>
                {data.steps?.map((step, index) => {
                  const isEdited = editedIndex === index;
                  const isAffected = editedIndex !== null && index >= editedIndex;
                  const currentBlock = editableBlocks[index] ?? step.block_hex;
                  const invalid = currentBlock.length !== expectedHexLen;
                  return (
                    <div
                      key={step.index}
                      className={`pa7-chain-step${isAffected ? " pa7-chain-step-affected" : ""}`}
                      style={{ animationDelay: `${index * 90}ms` }}
                    >
                      <div className="pa7-chain-arrow">→</div>
                      <div className={`pa7-block-card${isEdited ? " pa7-block-card-edited" : ""}${invalid ? " pa7-block-card-invalid" : ""}`}>
                        <div className="pa7-card-top">
                          <span className="pa7-step-chip">M{step.index}</span>
                          <span className="pa7-card-caption">Editable padded block</span>
                        </div>
                        <input
                          value={currentBlock}
                          onChange={e => updateBlock(index, e.target.value)}
                          className="input mono pa7-block-input"
                        />
                        <span className="pa7-card-hint">
                          {invalid ? `Need ${expectedHexLen} hex chars` : "Change this block to replay the suffix of the chain"}
                        </span>
                      </div>
                      <div className={`pa7-state-node${isAffected ? " pa7-state-node-affected" : ""}`}>
                        <span className="pa7-node-kicker">Compression input</span>
                        <span className="pa7-node-title">z{step.index - 1}</span>
                        <code className="pa7-node-hex">{step.chaining_in_hex}</code>
                      </div>
                      <div className="pa7-compress-pill">h(z, M)</div>
                      <div className={`pa7-state-node pa7-state-node-output${isAffected ? " pa7-state-node-affected" : ""}`}>
                        <span className="pa7-node-kicker">Compression output</span>
                        <span className="pa7-node-title">z{step.index}</span>
                        <code className="pa7-node-hex">{step.chaining_out_hex}</code>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          )}
        </ResultArea>
      }
    />
  );
}

export function PA7CollisionPanel() {
  const { loading, data, error, run } = useAsync(api.pa7Collision);
  const [autoPlay, setAutoPlay] = useState(false);
  const [activeStage, setActiveStage] = useState(0);

  useEffect(() => {
    if (!data || !autoPlay) {
      return;
    }
    const maxStage = (data.trace1?.steps?.length ?? 0) + 1;
    const timer = setInterval(() => {
      setActiveStage(prev => {
        if (prev >= maxStage) {
          setAutoPlay(false);
          return maxStage;
        }
        return prev + 1;
      });
    }, 950);
    return () => clearInterval(timer);
  }, [autoPlay, data]);

  const renderCollisionTrace = (trace, label, accentClass) => {
    if (!trace) return null;
    return (
      <div className={`pa7-collision-trace ${accentClass}`}>
        <div className="pa7-collision-trace-head">
          <span className="pa7-collision-trace-label">{label}</span>
          <code className="pa7-collision-trace-message">{trace.message_hex}</code>
        </div>
        <div className="pa7-collision-rail">
          <div className="pa7-state-node pa7-state-root">
            <span className="pa7-node-kicker">Initial state</span>
            <span className="pa7-node-title">z₀ = IV</span>
            <code className="pa7-node-hex">{trace.iv_hex}</code>
          </div>
          {trace.steps?.map((step, index) => {
            const isFirst = index === 0;
            const isLast = index === (trace.steps?.length ?? 1) - 1;
            const isActive = activeStage === index + 1;
            const isRevealed = activeStage >= index + 1;
            return (
              <div
                key={`${label}-${step.index}`}
                className={`pa7-collision-step${isFirst ? " pa7-collision-step-hit" : ""}${isLast ? " pa7-collision-step-final" : ""}${isActive ? " pa7-collision-step-active" : ""}${!isRevealed ? " pa7-collision-step-muted" : ""}`}
                style={{ animationDelay: `${index * 100}ms` }}
              >
                <div className="pa7-chain-arrow">→</div>
                <div className={`pa7-block-card${isFirst ? " pa7-block-card-edited" : ""}`}>
                  <div className="pa7-card-top">
                    <span className="pa7-step-chip">M{step.index}</span>
                    <span className="pa7-card-caption">{isFirst ? "Collision entry block" : "Identical suffix block"}</span>
                  </div>
                  <code className="pa7-node-hex">{step.block_hex}</code>
                </div>
                <div className={`pa7-state-node${isFirst ? " pa7-state-node-affected" : ""}`}>
                  <span className="pa7-node-kicker">Compression input</span>
                  <span className="pa7-node-title">z{step.index - 1}</span>
                  <code className="pa7-node-hex">{step.chaining_in_hex}</code>
                </div>
                <div className="pa7-compress-pill">h(z, M)</div>
                <div className={`pa7-state-node pa7-state-node-output${isLast ? " pa7-state-node-affected" : ""}`}>
                  <span className="pa7-node-kicker">{isLast ? "Final digest" : "Compression output"}</span>
                  <span className="pa7-node-title">z{step.index}</span>
                  <code className="pa7-node-hex">{step.chaining_out_hex}</code>
                </div>
              </div>
            );
          })}
        </div>
      </div>
    );
  };

  return (
    <PanelCard
      title="Collision Propagation"
      formula={"h(m_1)=h(m_2) \\Rightarrow H(m_1)=H(m_2)"}
      desc="This uses two distinct equal-length messages that collide in the first toy compression step. Because MD-strengthening appends the same final padding block to both, the remaining chain is identical and the full hashes collide too."
      fullWidth
      inputContent={
        <>
          <p style={{ fontSize: 13, color: "var(--text-3)", margin: "0 0 8px" }}>
            Messages are fixed to the built-in toy collision pair from the PA7 backend so the reduction is deterministic and easy to inspect.
          </p>
          <button
            className="btn-primary"
            onClick={() => {
              setAutoPlay(false);
              setActiveStage(0);
              run({});
            }}
            disabled={loading}
          >
            {loading ? <><Spinner /> Demonstrating…</> : "Run Collision Demo"}
          </button>
          {data && (
            <div className="pa7-collision-controls">
              <button
                className="btn-secondary"
                onClick={() => {
                  setActiveStage(0);
                  setAutoPlay(true);
                }}
              >
                Autoplay Proof
              </button>
              <button
                className="btn-secondary"
                onClick={() => {
                  setAutoPlay(false);
                  setActiveStage(prev => Math.max(0, prev - 1));
                }}
              >
                Step Back
              </button>
              <button
                className="btn-secondary"
                onClick={() => {
                  setAutoPlay(false);
                  setActiveStage(prev => Math.min((data.trace1?.steps?.length ?? 0) + 1, prev + 1));
                }}
              >
                Step Forward
              </button>
            </div>
          )}
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && (
            <div className="result-structured pa7-collision-wrap">
              <div className="result-row pa7-summary-row">
                <Badge variant={data.hash_collision ? "pass" : "fail"}>
                  {data.hash_collision ? "Collision Propagates" : "No Collision"}
                </Badge>
                <Badge variant={data.compression_collision ? "pass" : "fail"}>
                  Compression collision: {String(data.compression_collision)}
                </Badge>
                <Badge variant={data.messages_distinct ? "info" : "fail"}>
                  Distinct inputs: {String(data.messages_distinct)}
                </Badge>
              </div>
              <div className="pa7-collision-legend">
                <div className="pa7-legend-item"><span className="pa7-legend-swatch pa7-legend-swatch-hit" /> Collision-causing first block</div>
                <div className="pa7-legend-item"><span className="pa7-legend-swatch pa7-legend-swatch-suffix" /> Identical suffix after the collision</div>
                <div className="pa7-legend-item"><span className="pa7-legend-swatch pa7-legend-swatch-digest" /> Final matching digest</div>
                <div className="pa7-legend-item"><span className="pa7-legend-swatch pa7-legend-swatch-active" /> Current autoplay focus</div>
              </div>
              <div className="pa7-collision-proofbar">
                <div className="pa7-collision-proofitem">
                  <span className="pa7-collision-proofkicker">First-step output</span>
                  <code className="hex-output">{data.compression_output_hex}</code>
                </div>
                <div className="pa7-collision-proofeq">=</div>
                <div className="pa7-collision-proofitem">
                  <span className="pa7-collision-proofkicker">Final digest</span>
                  <code className="hex-output">{data.hash1_hex}</code>
                </div>
              </div>
              <div className="pa7-collision-callout">
                <strong>Why it works:</strong> the two different first blocks land on the same chaining value, and after that both traces process the same padding block sequence, so the whole suffix of the computation is identical.
              </div>
              <div className="pa7-collision-stage">
                <div className={`pa7-collision-connector${activeStage > 0 ? " pa7-collision-connector-live" : ""}`}>
                  <div className="pa7-collision-connector-line" />
                  <div className="pa7-collision-connector-badge">
                    {activeStage === 0 ? "Ready" : activeStage === 1 ? "Collision" : activeStage <= (data.trace1?.steps?.length ?? 0) ? `Suffix Step ${activeStage}` : "Same Digest"}
                  </div>
                </div>
                <div className="pa7-collision-grid">
                {renderCollisionTrace(data.trace1, "Message A", "pa7-collision-left")}
                {renderCollisionTrace(data.trace2, "Message B", "pa7-collision-right")}
                </div>
              </div>
              <div className="result-field">
                <span className="result-field-label">Explanation</span>
                <span className="result-desc">{data.explanation}</span>
              </div>
            </div>
          )}
        </ResultArea>
      }
    />
  );
}

export function PA8HashPanel() {
  const [message, setMessage] = useState("hello dlp hash");
  const [paramMode, setParamMode] = useState("full");
  const [outputMode, setOutputMode] = useState("full");
  const { loading, data, error, run } = useAsync(api.pa8Hash);

  const submit = () => run({
    message,
    use_toy_params: paramMode === "toy",
    output_bits: outputMode === "full" ? undefined : Number(outputMode),
  });

  return (
    <PanelCard
      title="DLP-Based CRHF"
      formula={"z_i = g^{x_i} \\cdot \\hat{h}^{m_i} \\bmod p"}
      desc="Uses the PA#7 Merkle-Damgard framework with the PA#8 DLP compression function. You can view the full digest or a toy 8, 12, or 16-bit truncation while keeping the same chain trace."
      fullWidth
      inputContent={(
        <>
          <Field label="Message" hint="Arbitrary-length input. The backend reuses PA#7 MD-strengthening before hashing block-by-block.">
            <textarea
              value={message}
              onChange={e => setMessage(e.target.value)}
              className="input"
              rows={4}
              style={{ resize: "vertical", minHeight: 96 }}
            />
          </Field>
          <Field label="Parameter set">
            <SegControl
              value={paramMode}
              onChange={setParamMode}
              options={[
                { value: "full", label: "Full subgroup" },
                { value: "toy", label: "Toy subgroup" },
              ]}
            />
          </Field>
          <Field label="Output mode">
            <SegControl
              value={outputMode}
              onChange={setOutputMode}
              options={[
                { value: "full", label: "Full digest" },
                { value: "8", label: "8-bit" },
                { value: "12", label: "12-bit" },
                { value: "16", label: "16-bit" },
              ]}
            />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Hashingâ€¦</> : "Compute PA8 Hash"}
          </button>
        </>
      )}
      outputContent={(
        <ResultArea loading={loading} error={error} data={data}>
          {data && (
            <div className="result-structured">
              <div className="result-row" style={{ flexWrap: "wrap", gap: 8 }}>
                <Badge variant="info">{data.parameter_set}</Badge>
                <Badge variant="pass">{data.output_bits} bits shown</Badge>
                <span className="result-label">{data.message_length_bytes} bytes {"->"} {data.blocks_hex?.length} blocks</span>
              </div>
              <div className="result-field">
                <span className="result-field-label">Digest</span>
                <code className="hex-output">{data.digest_hex}</code>
              </div>
              {data.full_digest_hex !== data.digest_hex && (
                <div className="result-field">
                  <span className="result-field-label">Full digest</span>
                  <code className="hex-output">{data.full_digest_hex}</code>
                </div>
              )}
              <div className="result-field">
                <span className="result-field-label">Public parameters</span>
                <div style={{ display: "grid", gap: 6 }}>
                  <code className="hex-output">g = {data.g_hex}</code>
                  <code className="hex-output">h_hat = {data.h_hat_hex}</code>
                </div>
              </div>
              <div className="result-field">
                <span className="result-field-label">Merkle-Damgard trace</span>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>Step</th>
                      <th>z(i-1) mod q</th>
                      <th>Mi mod q</th>
                      <th>z(i)</th>
                    </tr>
                  </thead>
                  <tbody>
                    {data.steps?.map(step => (
                      <tr key={step.index}>
                        <td>{step.index}</td>
                        <td><code>{step.chaining_value_zq}</code></td>
                        <td><code>{step.block_value_zq}</code></td>
                        <td><code>{step.chaining_out_hex}</code></td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </ResultArea>
      )}
    />
  );
}

export function PA8CollisionPanel() {
  const [bits, setBits] = useState("16");
  const [maxAttempts, setMaxAttempts] = useState(50000);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);
  const [data, setData] = useState(null);
  const [attemptCounter, setAttemptCounter] = useState(0);
  const abortRef = useRef(false);

  useEffect(() => {
    return () => {
      abortRef.current = true;
    };
  }, []);

  const randomMessageHex = (byteLength = 8) => {
    const bytes = new Uint8Array(byteLength);
    globalThis.crypto.getRandomValues(bytes);
    return Array.from(bytes, b => b.toString(16).padStart(2, "0")).join("");
  };

  const submit = async () => {
    const bitCount = Number(bits);
    const cap = Number(maxAttempts);
    const seen = new Map();
    abortRef.current = false;
    setLoading(true);
    setError(null);
    setData(null);
    setAttemptCounter(0);

    try {
      for (let attempt = 1; attempt <= cap; attempt += 1) {
        const messageHex = randomMessageHex();
        const result = await api.pa8HashTruncated({
          message_hex: messageHex,
          output_bits: bitCount,
          use_toy_params: true,
        });
        const previous = seen.get(result.digest_hex);
        if (previous && previous !== messageHex) {
          setAttemptCounter(attempt);
          let reductionDemo = null;
          try {
            const backendResult = await api.pa8Collision({ bits: bitCount, max_attempts: 50000 });
            reductionDemo = backendResult.compression_reduction_demo ?? null;
          } catch (_) { /* optional enrichment */ }
          setData({
            bits: bitCount,
            attempts: attempt,
            message1_hex: previous,
            message2_hex: messageHex,
            truncated_digest_hex: result.digest_hex,
            expected_birthday_work: Math.pow(2, bitCount / 2),
            compression_reduction_demo: reductionDemo,
          });
          return;
        }
        seen.set(result.digest_hex, messageHex);

        if (attempt % 8 === 0) {
          setAttemptCounter(attempt);
          await new Promise(resolve => setTimeout(resolve, 0));
        }
        if (abortRef.current) {
          return;
        }
      }
      throw new Error("No collision found within the selected attempt budget");
    } catch (e) {
      setError(e.message);
    } finally {
      setLoading(false);
    }
  };

  const expectedWork = Math.pow(2, Number(bits) / 2);
  const progressRatio = Math.min(1, attemptCounter / expectedWork);

  return (
    <PanelCard
      title="Collision Hunt"
      formula={"H_n(M) = H(M) \\bmod 2^n"}
      desc="Searches for a birthday collision on the toy PA#8 hash using 8, 12, or 16-bit truncation. The response includes the final attempt count and a toy compression-collision reduction check."
      fullWidth
      inputContent={(
        <>
          <Field label="Truncation">
            <SegControl
              value={bits}
              onChange={setBits}
              options={[
                { value: "8", label: "8-bit" },
                { value: "12", label: "12-bit" },
                { value: "16", label: "16-bit" },
              ]}
            />
          </Field>
          <Field label="Max attempts" hint="The demo uses the toy subgroup so the birthday search stays fast in the browser workflow.">
            <input
              type="number"
              min={32}
              max={500000}
              value={maxAttempts}
              onChange={e => setMaxAttempts(e.target.value)}
              className="input"
              style={{ width: "140px" }}
            />
          </Field>
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Huntingâ€¦</> : "Find Collision"}
          </button>
        </>
      )}
      outputContent={(
        <div className="result-area">
          {loading && (
            <div className="result-structured">
              <div className="result-row" style={{ gap: 8, flexWrap: "wrap" }}>
                <Badge variant="info">Toy subgroup</Badge>
                <Badge variant="warn">Searching</Badge>
              </div>
              <div className="result-field">
                <span className="result-field-label">Attempts</span>
                <span className="result-val"><Spinner /> {attemptCounter}</span>
              </div>
              <div className="result-field">
                <span className="result-field-label">Progress toward birthday bound</span>
                <div className="ratio-bar-wrap">
                  <div className="ratio-bar">
                    <div className="ratio-fill" style={{ width: `${progressRatio * 100}%` }} />
                  </div>
                  <span className="ratio-label">
                    {attemptCounter} / {expectedWork} expected attempts ({(progressRatio * 100).toFixed(1)}%)
                  </span>
                </div>
              </div>
              <div className="result-field">
                <span className="result-field-label">Target</span>
                <span className="result-desc">Looking for a {bits}-bit truncated collision in the background.</span>
              </div>
            </div>
          )}
          {!loading && error && (
            <div className="result-error">
              <span className="result-error-label">Error</span>
              <pre>{error}</pre>
            </div>
          )}
          {!loading && !error && !data && (
            <div className="result-empty"><span>Results will appear here</span></div>
          )}
          {!loading && data && (
            <div className="result-structured">
              <div className="result-row" style={{ flexWrap: "wrap", gap: 8 }}>
                <Badge variant="pass">Collision Found</Badge>
                <Badge variant="info">{data.bits}-bit truncation</Badge>
                <span className="result-label">{data.attempts} attempts</span>
              </div>
              <div className="result-field">
                <span className="result-field-label">Shared truncated digest</span>
                <code className="hex-output">{data.truncated_digest_hex}</code>
              </div>
              <div className="result-field">
                <span className="result-field-label">Input A</span>
                <code className="hex-output">{data.message1_hex}</code>
              </div>
              <div className="result-field">
                <span className="result-field-label">Input B</span>
                <code className="hex-output">{data.message2_hex}</code>
              </div>
              <div className="result-field">
                <span className="result-field-label">Birthday baseline</span>
                <span className="result-val">expected work &asymp; {data.expected_birthday_work}</span>
              </div>
              <div className="result-field">
                <span className="result-field-label">Where the collision landed</span>
                <div className="ratio-bar-wrap">
                  <div className="ratio-bar">
                    <div className="ratio-fill" style={{ width: `${Math.min(100, (data.attempts / data.expected_birthday_work) * 100)}%` }} />
                  </div>
                  <span className="ratio-label">
                    {(data.attempts / data.expected_birthday_work).toFixed(2)} × the expected birthday point
                  </span>
                </div>
              </div>
              {data.compression_reduction_demo && (
                <div className="result-field">
                  <span className="result-field-label">DLP Security Reduction</span>
                  <div style={{ display: "flex", flexDirection: "column", gap: 6 }}>
                    <span className="result-desc">
                      A compression collision recovers the secret discrete log &alpha; such that
                      ĥ = g<sup>&alpha;</sup> mod p.
                    </span>
                    <code className="hex-output">
                      recovered &alpha; = {data.compression_reduction_demo.recovered_alpha}
                    </code>
                    <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
                      <Badge variant={data.compression_reduction_demo.recovery_matches ? "pass" : "fail"}>
                        {data.compression_reduction_demo.recovery_matches ? "Matches expected \u03b1" : "Mismatch"}
                      </Badge>
                      <span className="result-hint">
                        Collision found in {data.compression_reduction_demo.attempts} compression attempts
                      </span>
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    />
  );
}
