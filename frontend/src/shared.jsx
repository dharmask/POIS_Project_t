/* eslint-disable react-refresh/only-export-components */
import React, { useState } from "react";
import katex from "katex";

// ─── Async hook ───────────────────────────────────────────────────────────────
export function useAsync(fn) {
  const [loading, setLoading] = useState(false);
  const [data, setData] = useState(null);
  const [error, setError] = useState(null);
  const run = async (...args) => {
    setLoading(true); setData(null); setError(null);
    try { setData(await fn(...args)); }
    catch (e) { setError(e.message); }
    finally { setLoading(false); }
  };
  return { loading, data, error, run };
}

// ─── Math rendering ──────────────────────────────────────────────────────────
export function Math({ expr, block = false }) {
  const html = katex.renderToString(expr, { throwOnError: false, displayMode: block });
  return (
    <span
      className={block ? "math-block" : "math-inline"}
      dangerouslySetInnerHTML={{ __html: html }}
    />
  );
}

// ─── Primitives ───────────────────────────────────────────────────────────────
export function Spinner() {
  return <span className="spinner" aria-label="Loading" />;
}

export function Badge({ variant = "info", children }) {
  return <span className={`badge badge-${variant}`}>{children}</span>;
}

export function Field({ label, hint, children }) {
  return (
    <div className="field">
      <span className="field-label">{label}</span>
      {hint && <span className="field-hint">{hint}</span>}
      {children}
    </div>
  );
}

export function FormulaBox({ expr }) {
  return (
    <div className="formula-box">
      <Math expr={expr} block />
    </div>
  );
}

export function SegControl({ value, onChange, options }) {
  return (
    <div className="seg-control">
      {options.map(o => (
        <button
          key={o.value}
          type="button"
          className={`seg-btn ${value === o.value ? "seg-active" : ""}`}
          onClick={() => onChange(o.value)}
        >
          {o.label}
        </button>
      ))}
    </div>
  );
}

export function ResultArea({ loading, error, data, children }) {
  if (loading) return (
    <div className="result-area result-loading">
      <Spinner /><span>Computing…</span>
    </div>
  );
  if (error) return (
    <div className="result-area result-error">
      <span className="result-error-label">Error</span>
      <pre>{error}</pre>
    </div>
  );
  if (children) return <div className="result-area">{children}</div>;
  if (!data)    return <div className="result-area result-empty"><span>Results will appear here</span></div>;
  return (
    <div className="result-area">
      <pre className="mono-pre">{JSON.stringify(data, null, 2)}</pre>
    </div>
  );
}

export function PanelCard({ title, formula, desc, inputContent, outputContent, fullWidth = false }) {
  return (
    <div className="panel-card">
      <div className="panel-card-header">
        <div className="panel-title-row">
          <span className="panel-title">{title}</span>
          {formula && <FormulaBox expr={formula} />}
        </div>
        {desc && <p className="panel-desc">{desc}</p>}
      </div>
      <div className={fullWidth ? "panel-body-full" : "panel-body-split"}>
        <div className="panel-input">{inputContent}</div>
        <div className="panel-output">{outputContent}</div>
      </div>
    </div>
  );
}

// ─── Result renderers ─────────────────────────────────────────────────────────
export function OWFResult({ data }) {
  if (!data) return null;
  const isDlp = data.mode === "dlp";
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant="info">{isDlp ? "DLP" : "AES-128"}</Badge>
        <span className="result-label">
          {isDlp
            ? <>Input: <code>{data.input}</code></>
            : <>Key: <code>{data.input_hex?.slice(0, 8)}…</code></>}
        </span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Output</span>
        <code className="hex-output">{data.output_hex}</code>
      </div>
      {data.output_bits && (
        <div className="result-field">
          <span className="result-field-label">Bit length</span>
          <span className="result-val">{data.output_bits} bits</span>
        </div>
      )}
      <div className="result-field">
        <span className="result-field-label">Construction</span>
        <span className="result-desc">{data.description}</span>
      </div>
    </div>
  );
}

export function PRGResult({ data }) {
  if (!data) return null;
  const r = data.statistics?.ones_ratio ?? 0.5;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant="info">{data.mode?.toUpperCase()}</Badge>
        <span className="result-label">{data.output_bits?.toLocaleString()} bits generated</span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Output (hex)</span>
        <code className="hex-output">{data.output_hex}</code>
      </div>
      {data.statistics && (
        <div className="result-field">
          <span className="result-field-label">Bit balance</span>
          <div className="ratio-bar-wrap">
            <div className="ratio-bar">
              <div className="ratio-fill" style={{ width: `${r * 100}%` }} />
            </div>
            <span className="ratio-label">
              {(r * 100).toFixed(1)}% ones · {((1 - r) * 100).toFixed(1)}% zeros
              &nbsp;({data.statistics.ones} / {data.statistics.zeros})
            </span>
          </div>
        </div>
      )}
    </div>
  );
}

export function NISTResult({ data }) {
  if (!data) return null;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant={data.overall_pass ? "pass" : "fail"}>
          {data.overall_pass ? "All Tests Passed" : "Some Tests Failed"}
        </Badge>
        <span className="result-label">{data.n_bits?.toLocaleString()} bits tested</span>
      </div>
      <table className="data-table">
        <thead>
          <tr><th>Test</th><th>p-value</th><th>Result</th></tr>
        </thead>
        <tbody>
          {data.tests?.map(t => (
            <tr key={t.test}>
              <td>{t.test}</td>
              <td><code>{t.p_value?.toFixed(6) ?? "N/A"}</code></td>
              <td><Badge variant={t.pass ? "pass" : "fail"}>{t.pass ? "PASS" : "FAIL"}</Badge></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

export function PRFResult({ data }) {
  if (!data) return null;
  const bits = data.input_bits ?? 8;
  const x = data.input ?? 0;
  const path = Array.from({ length: bits }, (_, i) => (x >> (bits - 1 - i)) & 1);
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant="info">{data.mode === "ggm" ? "GGM Tree" : "AES PRF"}</Badge>
        <span className="result-label">
          <Math expr={`F_k(${data.input})`} />
        </span>
      </div>
      {data.mode === "ggm" && (
        <div className="result-field">
          <span className="result-field-label">Tree path ({bits} levels)</span>
          <div className="ggm-path">
            {path.map((bit, i) => (
              <span key={i} className={`ggm-step ggm-${bit ? "right" : "left"}`}>
                {bit ? "R" : "L"}
              </span>
            ))}
          </div>
          <span className="path-code">{x.toString(2).padStart(bits, "0")}</span>
        </div>
      )}
      <div className="result-field">
        <span className="result-field-label">Output (hex, 128 bits)</span>
        <code className="hex-output">{data.output_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Output (integer)</span>
        <code>{data.output_int?.toString()}</code>
      </div>
    </div>
  );
}

export function PRGFromPRFResult({ data }) {
  if (!data) return null;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant="info">{data.n_bytes} bytes</Badge>
        <span className="result-label">seed = {data.seed}</span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Output (first 32 bytes)</span>
        <code className="hex-output">{data.output_hex?.slice(0, 64)}{data.output_hex?.length > 64 ? "…" : ""}</code>
      </div>
      {data.nist_tests?.length > 0 && (
        <div className="result-field">
          <span className="result-field-label">NIST Quick-Check</span>
          <div className="nist-mini">
            {data.nist_tests.map(t => (
              <Badge key={t.test} variant={t.pass ? "pass" : "fail"}>
                {t.test}: {t.pass ? "✓" : "✗"}
              </Badge>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}

export function DistGameResult({ data }) {
  if (!data) return null;
  const indist = data.verdict === "indistinguishable";
  const dist = data.statistical_distance;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant={indist ? "pass" : "warn"}>
          {indist ? "Indistinguishable" : "Distinguishable"}
        </Badge>
      </div>
      {dist !== undefined && (
        <div className="result-field">
          <span className="result-field-label">Statistical distance</span>
          <span className={`result-val ${dist < 0.15 ? "text-pass" : "text-fail"}`}>
            {dist.toFixed(4)}
          </span>
          <span className="result-hint">threshold: &lt; 0.15 → secure</span>
        </div>
      )}
      {data.n_queries && (
        <div className="result-field">
          <span className="result-field-label">Oracle queries</span>
          <span className="result-val">{data.n_queries}</span>
        </div>
      )}
      <div className="result-field">
        <span className="result-field-label">Full response</span>
        <pre className="mono-pre">{JSON.stringify(data, null, 2)}</pre>
      </div>
    </div>
  );
}

// ─── PA3 Result Renderers ─────────────────────────────────────────────────────

export function PRPResult({ data }) {
  if (!data) return null;
  const sw = data.switching_lemma;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant="info">{data.direction === "forward" ? "F_k(x)" : "F_k⁻¹(y)"}</Badge>
        <Badge variant={data.bijection_verified ? "pass" : "fail"}>
          {data.bijection_verified ? "Bijection ✓" : "Bijection ✗"}
        </Badge>
      </div>
      <div className="result-field">
        <span className="result-field-label">Input</span>
        <code className="hex-output">{data.input_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Output</span>
        <code className="hex-output">{data.output_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Description</span>
        <span className="result-desc">{data.description}</span>
      </div>
      {sw && (
        <div className="result-field">
          <span className="result-field-label">PRP–PRF Switching Bound (q=10)</span>
          <span className="result-val">{sw.bound_sci}</span>
          <span className="result-hint">{sw.formula}</span>
        </div>
      )}
    </div>
  );
}

export function ModesResult({ data }) {
  if (!data) return null;
  const isECB = data.mode === "ecb";
  const pd = data.pattern_demo;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant="info">{data.mode?.toUpperCase()}</Badge>
        <Badge variant={isECB ? "fail" : "pass"}>
          {isECB ? "Insecure" : "CPA-Secure"}
        </Badge>
      </div>
      {(data.iv_hex || data.nonce_hex) && (
        <div className="result-field">
          <span className="result-field-label">{data.iv_hex ? "IV" : "Nonce"}</span>
          <code className="hex-output">{data.iv_hex || data.nonce_hex}</code>
        </div>
      )}
      <div className="result-field">
        <span className="result-field-label">Ciphertext</span>
        <code className="hex-output">{data.ciphertext_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Decrypted</span>
        <span className="result-val">{data.decrypted}</span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Security</span>
        <span className="result-desc" style={{ color: isECB ? "var(--fail-t)" : "var(--pass-t)", fontWeight: 600 }}>
          {data.security}
        </span>
      </div>
      {isECB && pd && (
        <div className="result-field">
          <span className="result-field-label">Pattern Leak Demo</span>
          <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 4 }}>
            {pd.ciphertext_blocks?.map((b, i) => (
              <div key={i} style={{ display: "flex", alignItems: "center", gap: 8, fontSize: 12 }}>
                <span style={{ color: "var(--text-4)", width: 52, flexShrink: 0 }}>Block {i}</span>
                <code className="hex-output" style={{
                  flex: 1, padding: "3px 6px",
                  background: i < 2 && pd.identical_blocks_leaked ? "rgba(220,38,38,0.07)" : undefined,
                  borderColor: i < 2 && pd.identical_blocks_leaked ? "rgba(220,38,38,0.3)" : undefined,
                }}>{b}</code>
                {i < 2 && pd.identical_blocks_leaked && (
                  <Badge variant="fail">SAME</Badge>
                )}
              </div>
            ))}
          </div>
          <span className="result-hint" style={{ color: "var(--fail-t)", marginTop: 4 }}>{pd.insight}</span>
        </div>
      )}
    </div>
  );
}

export function PaddingOracleResult({ data }) {
  if (!data) return null;
  const atk = data.attack;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant="fail">CBC Broken</Badge>
        <span className="result-label">Queries used: {atk?.total_oracle_queries}</span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Original plaintext</span>
        <span className="result-val">{data.original_plaintext}</span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Recovered plaintext</span>
        <span className="result-val" style={{ color: "var(--pass-t)", fontWeight: 700 }}>
          {atk?.recovered_ascii}
        </span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Recovered hex</span>
        <code className="hex-output">{atk?.recovered_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Step trace (last 4 bytes)</span>
        <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 4 }}>
          {atk?.steps?.slice(-4).map((s, i) => (
            <div key={i} style={{ display: "flex", gap: 8, fontSize: 12, alignItems: "center" }}>
              <span style={{ color: "var(--text-4)", width: 44, flexShrink: 0 }}>byte[{s.byte_index}]</span>
              <span style={{ color: "var(--text-3)" }}>pad=0x{s.pad_byte?.toString(16)}</span>
              <span style={{ color: "var(--text-3)" }}>{s.guesses_tried} guesses</span>
              <code style={{ fontFamily: "var(--font-mono)", color: "var(--text-code)", fontSize: 11 }}>
                '{s.plaintext_byte_chr}'
              </code>
            </div>
          ))}
        </div>
      </div>
      <div className="result-field">
        <span className="result-hint" style={{ color: "var(--fail-t)" }}>{data.security_note}</span>
      </div>
    </div>
  );
}

// ─── PA4 Result Renderers ─────────────────────────────────────────────────────

export function MACResult({ data }) {
  if (!data) return null;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant="info">{data.mac_mode?.toUpperCase()}</Badge>
        {data.verified !== null && data.verified !== undefined && (
          <Badge variant={data.verified ? "pass" : "fail"}>
            {data.verified ? "Tag Valid ✓" : "Tag Invalid ✗"}
          </Badge>
        )}
      </div>
      <div className="result-field">
        <span className="result-field-label">Tag ({data.tag_bits} bits)</span>
        <code className="hex-output">{data.tag_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Description</span>
        <span className="result-desc">{data.description}</span>
      </div>
    </div>
  );
}

export function LengthExtResult({ data }) {
  if (!data) return null;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant={data.attack_succeeded ? "fail" : "warn"}>
          {data.attack_succeeded ? "Attack Succeeded!" : "Attack Demo"}
        </Badge>
        <Badge variant="pass">HMAC Immune ✓</Badge>
      </div>
      <div className="result-field">
        <span className="result-field-label">Original tag H(k‖m)</span>
        <code className="hex-output">{data.original_tag}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Extension appended</span>
        <span className="result-val" style={{ color: "var(--fail-t)", fontFamily: "var(--font-mono)", fontSize: 13 }}>
          {data.extension}
        </span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Attacker forged tag</span>
        <code className="hex-output">{data.attacker_forged_tag}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Server expected tag</span>
        <code className="hex-output">{data.server_expected_tag}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Tags match?</span>
        <Badge variant={data.attack_succeeded ? "fail" : "pass"}>
          {data.attack_succeeded ? "YES — forgery successful!" : "No match"}
        </Badge>
      </div>
      <div className="result-field">
        <span className="result-field-label">HMAC tag (immune)</span>
        <code className="hex-output">{data.hmac_tag}</code>
      </div>
      <span className="result-hint">{data.explanation}</span>
    </div>
  );
}

export function EUFCMAResult({ data }) {
  if (!data) return null;
  const secure = !data.forgery_attempt?.success;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant={secure ? "pass" : "fail"}>{data.verdict}</Badge>
        <Badge variant="info">{data.mac_mode?.toUpperCase()}</Badge>
      </div>
      <div className="result-field">
        <span className="result-field-label">Query sample (first 3)</span>
        <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 4 }}>
          {data.queries?.slice(0, 3).map((q, i) => (
            <div key={i} style={{ display: "flex", gap: 8, fontSize: 12 }}>
              <code style={{ color: "var(--text-3)", flexShrink: 0 }}>{q.message}</code>
              <span style={{ color: "var(--text-4)" }}>→</span>
              <code style={{ fontFamily: "var(--font-mono)", color: "var(--text-code)", fontSize: 11 }}>
                {q.tag?.slice(0, 16)}…
              </code>
            </div>
          ))}
        </div>
      </div>
      <div className="result-field">
        <span className="result-field-label">Forgery attempt on "{data.forgery_attempt?.new_message}"</span>
        <div style={{ display: "flex", flexDirection: "column", gap: 4, marginTop: 4 }}>
          <div style={{ fontSize: 12 }}>
            <span style={{ color: "var(--text-4)" }}>Replayed tag: </span>
            <code style={{ fontFamily: "var(--font-mono)", color: "var(--fail-t)", fontSize: 11 }}>
              {data.forgery_attempt?.replayed_tag?.slice(0, 16)}…
            </code>
          </div>
          <div style={{ fontSize: 12 }}>
            <span style={{ color: "var(--text-4)" }}>Correct tag:  </span>
            <code style={{ fontFamily: "var(--font-mono)", color: "var(--pass-t)", fontSize: 11 }}>
              {data.forgery_attempt?.correct_tag?.slice(0, 16)}…
            </code>
          </div>
        </div>
      </div>
      <span className="result-hint">{data.note}</span>
    </div>
  );
}

// ─── PA5 Result Renderers ─────────────────────────────────────────────────────

export function RSAKeygenResult({ data }) {
  if (!data) return null;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant="info">RSA-{data.bits}</Badge>
        <span className="result-label">{data.n_bits}-bit modulus</span>
      </div>
      <div className="result-field">
        <span className="result-field-label">p (hex)</span>
        <code className="hex-output">{data.p_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">q (hex)</span>
        <code className="hex-output">{data.q_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">n = p*q (hex)</span>
        <code className="hex-output">{data.n_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">e (public exponent)</span>
        <code>{data.e}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">d (private exponent, hex)</span>
        <code className="hex-output">{data.d_hex}</code>
      </div>
    </div>
  );
}

export function RSACryptResult({ data }) {
  if (!data) return null;
  const isEncrypt = data.ciphertext_hex !== undefined;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant="info">{isEncrypt ? "Encrypted" : "Decrypted"}</Badge>
      </div>
      {isEncrypt ? (
        <>
          <div className="result-field">
            <span className="result-field-label">Message (text)</span>
            <span className="result-val">{data.message_text}</span>
          </div>
          <div className="result-field">
            <span className="result-field-label">Ciphertext (hex)</span>
            <code className="hex-output">{data.ciphertext_hex}</code>
          </div>
        </>
      ) : (
        <>
          <div className="result-field">
            <span className="result-field-label">Decrypted (int)</span>
            <code>{data.decrypted_int}</code>
          </div>
          <div className="result-field">
            <span className="result-field-label">Decrypted (text)</span>
            <span className="result-val" style={{ color: "var(--pass-t)", fontWeight: 700 }}>{data.decrypted_text}</span>
          </div>
        </>
      )}
    </div>
  );
}

export function RSASignResult({ data }) {
  if (!data) return null;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant={data.verified ? "pass" : "fail"}>
          {data.verified ? "Signature Valid" : "Signature Invalid"}
        </Badge>
      </div>
      <div className="result-field">
        <span className="result-field-label">Signature (hex)</span>
        <code className="hex-output">{data.signature_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Construction</span>
        <span className="result-desc">{data.description}</span>
      </div>
    </div>
  );
}

export function RSACPAResult({ data }) {
  if (!data) return null;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant="fail">NOT CPA-Secure</Badge>
        <Badge variant={data.identical ? "fail" : "pass"}>
          {data.identical ? "Ciphertexts identical!" : "Different"}
        </Badge>
      </div>
      <div className="result-field">
        <span className="result-field-label">Ciphertext #1</span>
        <code>{data.ciphertext_1}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Ciphertext #2</span>
        <code>{data.ciphertext_2}</code>
      </div>
      <span className="result-hint" style={{ color: "var(--fail-t)" }}>{data.insight}</span>
    </div>
  );
}

export function DHExchangeResult({ data }) {
  if (!data) return null;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant={data.secrets_match ? "pass" : "fail"}>
          {data.secrets_match ? "Secrets Match" : "Mismatch!"}
        </Badge>
        <span className="result-label">{data.p_bits}-bit prime group</span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Alice's public key</span>
        <code className="hex-output">{data.alice_public_hex?.slice(0, 32)}...</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Bob's public key</span>
        <code className="hex-output">{data.bob_public_hex?.slice(0, 32)}...</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Shared secret (Alice)</span>
        <code className="hex-output">{data.alice_secret_hex?.slice(0, 32)}...</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Shared secret (Bob)</span>
        <code className="hex-output">{data.bob_secret_hex?.slice(0, 32)}...</code>
      </div>
      <span className="result-hint">{data.description}</span>
    </div>
  );
}

export function MITMResult({ data }) {
  if (!data) return null;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant="fail">MITM Attack Succeeded</Badge>
      </div>
      <div className="result-field">
        <span className="result-field-label">Alice-Mallory shared key</span>
        <Badge variant={data.alice_mallory_match ? "fail" : "pass"}>
          {data.alice_mallory_match ? "Compromised" : "Safe"}
        </Badge>
      </div>
      <div className="result-field">
        <span className="result-field-label">Bob-Mallory shared key</span>
        <Badge variant={data.bob_mallory_match ? "fail" : "pass"}>
          {data.bob_mallory_match ? "Compromised" : "Safe"}
        </Badge>
      </div>
      <div className="result-field">
        <span className="result-field-label">Alice-Bob real secret</span>
        <Badge variant={data.alice_bob_compromised ? "fail" : "pass"}>
          {data.alice_bob_compromised ? "Never established!" : "Secure"}
        </Badge>
      </div>
      <span className="result-hint" style={{ color: "var(--fail-t)" }}>{data.insight}</span>
    </div>
  );
}

export function AuthDHResult({ data }) {
  if (!data) return null;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant={data.alice_signature_valid ? "pass" : "fail"}>
          {data.alice_signature_valid ? "RSA Signature Valid" : "Signature Invalid"}
        </Badge>
        <Badge variant={data.shared_secret_match ? "pass" : "fail"}>
          {data.shared_secret_match ? "Secrets Match" : "Mismatch"}
        </Badge>
      </div>
      <div className="result-field">
        <span className="result-field-label">Alice's signed DH public key</span>
        <code className="hex-output">{data.alice_dh_public_hex?.slice(0, 32)}...</code>
      </div>
      <span className="result-hint">{data.description}</span>
    </div>
  );
}

// ─── OWF Hardness Result ─────────────────────────────────────────────────────
export function OWFHardnessResult({ data }) {
  if (!data) return null;
  const ratePercent = (data.success_rate * 100).toFixed(2);
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant={data.success_rate < 0.01 ? "pass" : "fail"}>
          {data.success_rate < 0.01 ? "Hardness Verified" : "WARNING: Weak"}
        </Badge>
        <Badge variant="info">{data.mode?.toUpperCase()}</Badge>
      </div>
      <div className="result-field">
        <span className="result-field-label">Inversion success rate</span>
        <span className="result-val">{data.successes} / {data.n_trials} = {ratePercent}%</span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Conclusion</span>
        <span className="result-desc">{data.conclusion}</span>
      </div>
      {data.trials?.length > 0 && (
        <div className="result-field">
          <span className="result-field-label">Sample trials (first {data.trials.length})</span>
          <table className="data-table">
            <thead><tr><th>x</th><th>f(x)</th><th>guess</th><th>hit?</th></tr></thead>
            <tbody>
              {data.trials.map((t, i) => (
                <tr key={i}>
                  <td><code>{String(t.x).slice(0, 8)}{String(t.x).length > 8 ? "…" : ""}</code></td>
                  <td><code>{String(t.y_hex).slice(0, 12)}…</code></td>
                  <td><code>{String(t.guess).slice(0, 8)}{String(t.guess).length > 8 ? "…" : ""}</code></td>
                  <td><Badge variant={t.hit ? "fail" : "pass"}>{t.hit ? "HIT" : "miss"}</Badge></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <div className="result-field">
        <span className="result-field-label">Construction</span>
        <span className="result-desc">{data.description}</span>
      </div>
    </div>
  );
}

// ─── OWF from PRG Result ──────────────────────────────────────────────────────
export function OWFFromPRGResult({ data }) {
  if (!data) return null;
  return (
    <div className="result-structured">
      <div className="result-row">
        <Badge variant={data.hardness_verified ? "pass" : "fail"}>
          {data.hardness_verified ? "Hardness Verified" : "Inversion Found!"}
        </Badge>
        <Badge variant="info">{data.mode?.toUpperCase()} PRG</Badge>
      </div>
      <div className="result-field">
        <span className="result-field-label">Seed</span>
        <code className="hex-output">{data.seed}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Full PRG output G(s)</span>
        <code className="hex-output">{data.full_prg_output_hex?.slice(0, 64)}{(data.full_prg_output_hex?.length ?? 0) > 64 ? "…" : ""}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">f(s) = G(s)</span>
        <code className="hex-output">{data.owf_output_hex?.slice(0, 64)}{(data.owf_output_hex?.length ?? 0) > 64 ? "…" : ""}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Random inversion attempts</span>
        <span className="result-val">{data.inversions_found} / {data.inversion_attempts} succeeded</span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Theorem</span>
        <span className="result-desc">{data.theorem}</span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Reduction</span>
        <span className="result-desc">{data.description}</span>
      </div>
    </div>
  );
}

// ─── Clique banner ────────────────────────────────────────────────────────────
export const ACTIVE_PRIMITIVES = {
  owf:    ["OWF"],
  prg:    ["OWF", "PRG"],
  nist:   ["OWF", "PRG"],
  prf:    ["OWF", "PRG", "PRF"],
  prgprf: ["OWF", "PRG", "PRF"],
  game:   ["OWF", "PRG", "PRF"],
  enc:    ["OWF", "PRG", "PRF"],
  dec:    ["OWF", "PRG", "PRF"],
  cpagame:["OWF", "PRG", "PRF"],
  prp:    ["OWF", "PRG", "PRF", "PRP"],
  ecb:    ["OWF", "PRG", "PRF", "PRP"],
  cbc:    ["OWF", "PRG", "PRF", "PRP"],
  ctr:    ["OWF", "PRG", "PRF", "PRP"],
  oracle: ["OWF", "PRG", "PRF", "PRP"],
  mac:    ["OWF", "PRG", "PRF", "PRP", "MAC"],
  lenext: ["OWF", "PRG", "PRF", "PRP", "MAC"],
  eufcma: ["OWF", "PRG", "PRF", "PRP", "MAC"],
  // PA5
  rsa:     ["OWF", "PRG", "PRF", "PRP", "MAC"],
  rsasign: ["OWF", "PRG", "PRF", "PRP", "MAC"],
  rsacpa:  ["OWF", "PRG", "PRF", "PRP", "MAC"],
  dh:      ["OWF", "PRG", "PRF", "PRP", "MAC"],
  mitm:    ["OWF", "PRG", "PRF", "PRP", "MAC"],
  authdh:  ["OWF", "PRG", "PRF", "PRP", "MAC"],
  mdhash:  ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"],
  collision: ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"],
  dlphash: ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"],
  hunt:    ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"],
  live:    ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"],
  compare: ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"],
  dlpattack: ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"],
  curve:   ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"],
  context: ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"],
  hmac:    ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"],
  cca:     ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"],
  security:["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"],
};

export function CliqueBanner({ page }) {
  const active = ACTIVE_PRIMITIVES[page] ?? [];
  const primitives = ["OWF", "PRG", "PRF", "PRP", "MAC", "CRHF"];
  return (
    <div className="clique-banner">
      {primitives.map((p, i) => (
        <span key={p}>
          <span className={`clique-node ${active.includes(p) ? "clique-active" : "clique-dim"}`}>{p}</span>
          {i < primitives.length - 1 && <span className="clique-arrow">⇔</span>}
        </span>
      ))}
    </div>
  );
}

// ─── Page metadata ────────────────────────────────────────────────────────────
export const PAGE_META = {
  owf: {
    pa: "PA #1", title: "One-Way Function",
    subtitle: "DLP-based or AES-based construction",
    desc: "Easy to compute, infeasible to invert — the hardness assumption underlying all of Minicrypt.",
  },
  prg: {
    pa: "PA #1", title: "Pseudorandom Generator",
    subtitle: "HILL / Goldreich-Levin Construction",
    formula: "G(x_0)\\,\\|\\,b(x_1)\\,\\|\\,\\cdots\\,\\|\\,b(x_\\ell)",
    desc: "Stretches a short seed to polynomially many pseudorandom bits via iterated OWF application.",
  },
  nist: {
    pa: "PA #1", title: "NIST SP 800-22 Statistical Tests",
    subtitle: "Frequency · Runs · Serial (m=2)",
    formula: "P\\text{-value} = \\operatorname{erfc}\\!\\left(\\tfrac{|S_n|}{\\sqrt{2n}}\\right) \\geq 0.01",
    desc: "Three NIST tests verify PRG output is statistically indistinguishable from true randomness.",
  },
  prf: {
    pa: "PA #2", title: "Pseudorandom Function",
    subtitle: "GGM Tree Construction",
    formula: "F_k(b_1\\cdots b_\\ell) = G_{b_\\ell}(\\cdots G_{b_1}(k)\\cdots)",
    desc: "Keyed function indistinguishable from a truly random function — constructed via a binary GGM tree.",
  },
  prgprf: {
    pa: "PA #2", title: "PRG from PRF",
    subtitle: "Bidirectional Reduction Demo",
    formula: "G_k(s) = F_k(s\\,\\|\\,0)\\,\\|\\,F_k(s\\,\\|\\,1)",
    desc: "Any secure PRF induces a secure PRG — closes the PRG ↔ PRF equivalence in the Minicrypt clique.",
  },
  game: {
    pa: "PA #2", title: "PRF Distinguishing Game",
    subtitle: "Security Experiment",
    formula: "\\left|\\Pr[\\mathcal{A}^{F_k}=1] - \\Pr[\\mathcal{A}^{R}=1]\\right| \\leq \\mathrm{negl}(n)",
    desc: "Empirically verifies PRF security: the adversary's distinguishing advantage must be negligible.",
  },
  enc: {
    pa: "PA #3", title: "CPA-Secure Encryption",
    subtitle: "Randomized encryption from a PRF",
    formula: "\\mathrm{Enc}_k(m) = r \\Vert (m \\oplus F_k(r\\Vert 0)\\Vert F_k(r\\Vert 1)\\cdots)",
    desc: "Uses the PA#2 PRF as a keystream generator with a fresh random nonce, giving privacy under chosen-plaintext attack.",
  },
  dec: {
    pa: "PA #3", title: "Decryption",
    subtitle: "Recover plaintext from nonce + keystream masking",
    formula: "\\mathrm{Dec}_k(r \\Vert c) = c \\oplus F_k(r\\Vert 0)\\Vert F_k(r\\Vert 1)\\cdots",
    desc: "Recomputes the same PRF-derived keystream and xors it with the ciphertext body to recover the message.",
  },
  cpagame: {
    pa: "PA #3", title: "IND-CPA Game",
    subtitle: "Secure randomized encryption vs broken deterministic encryption",
    formula: "\\left|\\Pr[\\mathcal{A}^{\\mathrm{Enc}_k}=1] - \\tfrac12\\right| \\leq \\mathrm{negl}(n)",
    desc: "Compares the secure randomized PRF-based scheme with the intentionally broken deterministic variant that reuses its nonce.",
  },
  // PA #4
  prp: {
    pa: "PA #4", title: "Pseudorandom Permutation",
    subtitle: "AES-128 as a PRP + PRP–PRF Switching Lemma",
    formula: "F_k(x) = \\text{AES}_k(x), \\quad F_k^{-1}(y) = \\text{AES}_k^{-1}(y)",
    desc: "AES is a keyed bijection indistinguishable from a random permutation. The switching lemma shows PRP ≈ PRF for polynomial query counts.",
  },
  ecb: {
    pa: "PA #4", title: "ECB Mode",
    subtitle: "Electronic Codebook — Not CPA-Secure",
    formula: "c_i = \\text{AES}_k(m_i)",
    desc: "Encrypts each block independently. Identical plaintext blocks produce identical ciphertext — pattern leakage makes ECB insecure.",
  },
  cbc: {
    pa: "PA #4", title: "CBC Mode",
    subtitle: "Cipher Block Chaining — CPA-Secure",
    formula: "c_i = \\text{AES}_k(m_i \\oplus c_{i-1}), \\quad c_0 = IV",
    desc: "CPA-secure with a random IV. Each block depends on all previous ciphertext. Sequential encryption, parallel decryption.",
  },
  ctr: {
    pa: "PA #4", title: "CTR Mode",
    subtitle: "Counter Mode — CPA-Secure, Parallelizable",
    formula: "c_i = m_i \\oplus \\text{AES}_k(\\text{nonce} \\Vert i)",
    desc: "Turns a block cipher into a stream cipher. Fully parallelizable. No padding. Nonce must never repeat with the same key.",
  },
  oracle: {
    pa: "PA #4", title: "Padding Oracle Attack",
    subtitle: "Breaking CBC with a Padding Oracle",
    formula: "m_i = D_k(c_i) \\oplus c_{i-1}",
    desc: "If a server reveals valid/invalid PKCS#7 padding, an adversary recovers any ciphertext byte-by-byte. CBC is not CCA-secure.",
  },
  // PA #4
  mac: {
    pa: "PA #5", title: "Message Authentication Code",
    subtitle: "PRF-MAC · CBC-MAC",
    formula: "\\mathrm{Mac}_k(m)=F_k(m)\\quad\\text{or}\\quad T_i=F_k(m_i\\oplus T_{i-1})",
    desc: "MAC provides integrity and authenticity. PA5 focuses on PRF→MAC and CBC-MAC; the HMAC construction itself is introduced separately in PA10.",
  },
  lenext: {
    pa: "PA #5", title: "Length-Extension Attack",
    subtitle: "Breaking Naive H(k‖m) MACs",
    formula: "H(k \\Vert m \\Vert \\text{pad} \\Vert m') = \\text{Extend}(H(k\\Vert m),\\ m')",
    desc: "Naive MAC = H(k‖m) is vulnerable to extension without knowing k. PA10’s HMAC fixes that with double wrapping.",
  },
  eufcma: {
    pa: "PA #5", title: "EUF-CMA Security Game",
    subtitle: "Existential Unforgeability under Chosen Message Attack",
    formula: "\\Pr[\\mathsf{Forge}] \\leq \\frac{q}{2^n}",
    desc: "Adversary makes q adaptive tag queries then attempts to forge. Bound is negligible for n=128 under the PRF assumption.",
  },
  // PA #5
  rsa: {
    pa: "Part III", title: "RSA Encryption",
    subtitle: "Key Generation + Encrypt / Decrypt",
    formula: "c = m^e \\bmod n, \\quad m = c^d \\bmod n",
    desc: "RSA key generation picks primes p, q, computes n=pq and d=e^{-1} mod phi(n). Security rests on the hardness of factoring n.",
  },
  rsasign: {
    pa: "Part III", title: "RSA Signatures",
    subtitle: "Sign + Verify",
    formula: "\\sigma = m^d \\bmod n, \\quad \\text{Verify: } m \\stackrel{?}{=} \\sigma^e \\bmod n",
    desc: "RSA signatures provide non-repudiation. The signer computes sigma = m^d mod n; anyone can verify with the public key (n, e).",
  },
  rsacpa: {
    pa: "Part III", title: "Textbook RSA is NOT CPA-Secure",
    subtitle: "Deterministic Encryption Demo",
    formula: "\\text{Enc}(m_1) = \\text{Enc}(m_2) \\Longrightarrow m_1 = m_2",
    desc: "Textbook RSA is deterministic: same message always produces the same ciphertext. An IND-CPA adversary wins with probability 1. Real RSA uses OAEP.",
  },
  dh: {
    pa: "Part III", title: "Diffie-Hellman Key Exchange",
    subtitle: "Alice and Bob agree on a shared secret",
    formula: "K = g^{ab} \\bmod p = B^a = A^b",
    desc: "Both parties independently compute the same shared secret. Security relies on the Decisional Diffie-Hellman (DDH) assumption.",
  },
  mitm: {
    pa: "Part III", title: "Man-in-the-Middle Attack",
    subtitle: "DH without Authentication is Insecure",
    formula: "K_{AM} \\neq K_{AB} \\neq K_{BM}",
    desc: "Without authentication, Mallory intercepts the key exchange and establishes separate shared keys with Alice and Bob. Digital signatures prevent this.",
  },
  authdh: {
    pa: "Part III", title: "Authenticated DH",
    subtitle: "RSA Signatures + DH Key Exchange",
    formula: "\\text{Verify}_{pk_A}(g^a) \\Rightarrow \\text{authentic}",
    desc: "Alice signs her DH public key with RSA. Bob verifies the signature before computing the shared secret, preventing man-in-the-middle attacks.",
  },
  mdhash: {
    pa: "PA #7", title: "Merkle-Damgard Chain Viewer",
    subtitle: "Generic hash from a fixed-length compression function",
    formula: "z_0 = IV,\\quad z_i = h(z_{i-1} \\Vert M_i),\\quad H(M)=z_\\ell",
    desc: "Applies MD-strengthening, splits the padded message into blocks, and shows each chaining value in order.",
  },
  collision: {
    pa: "PA #7", title: "Collision Propagation Demo",
    subtitle: "Why a collision in h becomes a collision in H",
    formula: "h(x)=h(x') \\Longrightarrow H(x)=H(x')",
    desc: "Uses the PA#7 toy compression function to show how a first-step collision propagates through the full Merkle-Damgard chain.",
  },
  dlphash: {
    pa: "PA #8", title: "DLP-Based Collision-Resistant Hash",
    subtitle: "PA#7 Merkle-Damgard with DLP compression",
    formula: "h(x,y)=g^x \\cdot \\hat{h}^{y} \\bmod p,\\quad H(M)=\\operatorname{MD}_{h}(M)",
    desc: "Hashes arbitrary-length inputs with the PA#7 Merkle-Damgard transform and a DLP-based compression function over a prime-order subgroup.",
  },
  hunt: {
    pa: "PA #8", title: "Birthday Collision Hunt",
    subtitle: "Toy subgroup with 8, 12, and 16-bit truncation",
    formula: "\\text{work} \\approx 2^{n/2}",
    desc: "Runs a birthday-style search over truncated PA#8 digests and reports the two colliding inputs, shared digest, and attempt count.",
  },
  live: {
    pa: "PA #9", title: "Live Birthday Attack Demo",
    subtitle: "Animated collision search on an n-bit hash",
    formula: "\\Pr[\\mathrm{collision\\ by\\ }q] \\approx 1 - e^{-q(q-1)/2^{n+1}}",
    desc: "Animates a collision search and overlays the standard birthday curve so the empirical stopping point can be compared against theory in real time.",
  },
  compare: {
    pa: "PA #9", title: "Naive vs Floyd",
    subtitle: "Time-space tradeoff for collision finding",
    formula: "\\text{work} \\approx 2^{n/2},\\quad \\text{space}_{\\mathrm{naive}} = O(k),\\quad \\text{space}_{\\mathrm{Floyd}} = O(1)",
    desc: "Compares the standard dictionary-based birthday attack with the space-efficient tortoise-and-hare approach over the same toy hash family.",
  },
  dlpattack: {
    pa: "PA #9", title: "Attack Truncated DLP Hash",
    subtitle: "PA#8 becomes easy to collide when n = 16",
    formula: "H_{16}(M) = H(M) \\bmod 2^{16}",
    desc: "Shows that truncating a secure collision-resistant hash to only 16 bits brings the collision cost down to the birthday bound.",
  },
  curve: {
    pa: "PA #9", title: "Empirical Birthday Curve",
    subtitle: "100 independent trials across several output sizes",
    formula: "1 - e^{-k(k-1)/2^{n+1}}",
    desc: "Plots the empirical collision distribution for n in {8,10,12,14,16} and overlays the theoretical birthday approximation.",
  },
  context: {
    pa: "PA #9", title: "MD5 / SHA-1 Context",
    subtitle: "Collision work translated into real time",
    formula: "\\text{attack time} = 2^{n/2} / R",
    desc: "Uses a modern hash rate estimate to show how much harder 160-bit collision search is than 128-bit collision search.",
  },
  hmac: {
    pa: "PA #10", title: "HMAC from the PA8 DLP Hash",
    subtitle: "Hash-based MAC without SHA-256",
    formula: "\\mathrm{HMAC}_k(m)=H((k\\oplus opad)\\Vert H((k\\oplus ipad)\\Vert m))",
    desc: "Instantiates HMAC with the PA8 DLP-based collision-resistant hash, so every layer still comes from the project’s own constructions.",
  },
  cca: {
    pa: "PA #10", title: "HMAC-Based CCA Encryption",
    subtitle: "Encrypt-then-HMAC using PA3 + PA8 + PA10",
    formula: "C=\\mathrm{Enc}_{k_{enc}}(m)\\Vert \\mathrm{HMAC}_{k_{mac}}(\\mathrm{Enc}_{k_{enc}}(m))",
    desc: "Builds a CCA-style authenticated encryption layer by encrypting first and then authenticating the ciphertext with the new HMAC construction.",
  },
  security: {
    pa: "PA #10", title: "CCA Security Demo",
    subtitle: "Tamper rejection before decryption",
    formula: "\\Pr[\\mathrm{tampered\\ ciphertext\\ accepted}] \\approx 0",
    desc: "Shows that bit-flips still deform bare CPA ciphertexts, while Encrypt-then-HMAC rejects the same tampering attempt before plaintext recovery.",
  },
};

// ─── Page header ──────────────────────────────────────────────────────────────
export function PageHeader({ pageKey }) {
  const meta = PAGE_META[pageKey];
  if (!meta) return null;
  return (
    <div className="page-header">
      <div className="page-header-top">
        <span className="page-pa-chip">{meta.pa}</span>
        <h2 className="page-title">{meta.title}</h2>
      </div>
      <p className="page-subtitle">{meta.subtitle}</p>
      {meta.formula && (
        <div className="page-formula">
          <Math expr={meta.formula} block />
        </div>
      )}
      <p className="page-desc">{meta.desc}</p>
    </div>
  );
}
