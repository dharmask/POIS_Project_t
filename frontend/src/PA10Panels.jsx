import React, { useEffect, useState } from "react";

import { api } from "./api";
import {
  Badge,
  Field,
  PanelCard,
  ResultArea,
  SegControl,
  Spinner,
  useAsync,
} from "./shared";

function HMACTraceResult({ data }) {
  if (!data) return null;
  return (
    <div className="result-structured">
      <div className="result-row" style={{ flexWrap: "wrap", gap: 8 }}>
        <Badge variant="info">PA8 DLP Hash</Badge>
        <Badge variant="pass">{data.tag_bits} bit tag</Badge>
        {data.verified !== null && data.verified !== undefined && (
          <Badge variant={data.verified ? "pass" : "fail"}>
            {data.verified ? "Tag Valid" : "Tag Invalid"}
          </Badge>
        )}
      </div>
      <div className="result-field">
        <span className="result-field-label">HMAC tag</span>
        <code className="hex-output">{data.tag_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Normalized key block</span>
        <code className="hex-output">{data.normalized_key_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Inner digest</span>
        <code className="hex-output">{data.inner_trace?.digest_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Outer digest</span>
        <code className="hex-output">{data.outer_trace?.digest_hex}</code>
      </div>
      <div className="result-field">
        <span className="result-field-label">Hash rounds</span>
        <span className="result-val">
          inner: {data.inner_trace?.steps?.length ?? 0} blocks | outer: {data.outer_trace?.steps?.length ?? 0} blocks
        </span>
      </div>
      <div className="result-field">
        <span className="result-field-label">Description</span>
        <span className="result-desc">{data.description}</span>
      </div>
    </div>
  );
}

export function PA10HMACPanel() {
  const [keyHex, setKeyHex] = useState("00112233445566778899aabbccddeeff");
  const [message, setMessage] = useState("PA10 uses the PA8 DLP hash inside HMAC.");
  const [verifyMode, setVerifyMode] = useState("compute");
  const [tagHex, setTagHex] = useState("");
  const { loading, data, error, run } = useAsync(api.pa10Hmac);

  const submit = () =>
    run({
      key_hex: keyHex,
      message,
      tag_hex: verifyMode === "verify" && tagHex.trim() ? tagHex.trim() : undefined,
    });

  return (
    <PanelCard
      title="HMAC from the PA8 DLP Hash"
      formula={"\\mathrm{HMAC}_k(m)=H((k\\oplus opad)\\|H((k\\oplus ipad)\\|m))"}
      desc="This is the real PA10 construction: the hash H is the PA8 DLP-based collision-resistant hash, not SHA-256."
      fullWidth
      inputContent={
        <>
          <Field label="Key" hint="Any hex key is accepted. Long keys are hashed down to one PA8 block before HMAC runs.">
            <input value={keyHex} onChange={(e) => setKeyHex(e.target.value)} className="input mono" />
          </Field>
          <Field label="Mode">
            <SegControl
              value={verifyMode}
              onChange={setVerifyMode}
              options={[
                { value: "compute", label: "Compute Tag" },
                { value: "verify", label: "Verify Tag" },
              ]}
            />
          </Field>
          <Field label="Message">
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              className="input"
              rows={4}
              style={{ resize: "vertical", minHeight: 96 }}
            />
          </Field>
          {verifyMode === "verify" && (
            <Field label="Candidate tag" hint="Paste a hex tag to check verification.">
              <input value={tagHex} onChange={(e) => setTagHex(e.target.value)} className="input mono" />
            </Field>
          )}
          <button className="btn-primary" onClick={submit} disabled={loading}>
            {loading ? <><Spinner /> Computing...</> : verifyMode === "verify" ? "Verify HMAC" : "Compute HMAC"}
          </button>
        </>
      }
      outputContent={
        <ResultArea loading={loading} error={error} data={data}>
          {data && <HMACTraceResult data={data} />}
        </ResultArea>
      }
    />
  );
}

function EncryptDecryptResult({ encryptData, decryptData }) {
  return (
    <div className="result-structured">
      {encryptData ? (
        <>
          <div className="result-row" style={{ flexWrap: "wrap", gap: 8 }}>
            <Badge variant="pass">Encrypt-then-HMAC</Badge>
            <Badge variant="info">{encryptData.tag_bits} bit authentication tag</Badge>
          </div>
          <div className="result-field">
            <span className="result-field-label">Ciphertext bundle</span>
            <code className="hex-output">{encryptData.ciphertext_hex}</code>
          </div>
          <div className="result-field">
            <span className="result-field-label">Ciphertext body</span>
            <code className="hex-output">{encryptData.ciphertext_body_hex}</code>
          </div>
          <div className="result-field">
            <span className="result-field-label">Appended HMAC tag</span>
            <code className="hex-output">{encryptData.tag_hex}</code>
          </div>
        </>
      ) : (
        <div className="result-empty"><span>Encryption results will appear here</span></div>
      )}
      {decryptData && (
        <>
          <div className="result-field">
            <span className="result-field-label">Decrypted plaintext</span>
            <span className="result-val">{decryptData.message_text}</span>
          </div>
          <div className="result-field">
            <span className="result-field-label">Recovered hex</span>
            <code className="hex-output">{decryptData.message_hex}</code>
          </div>
        </>
      )}
    </div>
  );
}

export function PA10CCAPanel() {
  const [keyHex, setKeyHex] = useState("11223344556677889900aabbccddeeff");
  const [message, setMessage] = useState("Assignment 10 end-to-end demo");
  const [cipherHex, setCipherHex] = useState("");
  const encrypt = useAsync(api.pa10Encrypt);
  const decrypt = useAsync(api.pa10Decrypt);

  useEffect(() => {
    if (encrypt.data?.ciphertext_hex) {
      setCipherHex(encrypt.data.ciphertext_hex);
    }
  }, [encrypt.data]);

  const runEncrypt = () => {
    encrypt.run({
      key_hex: keyHex,
      message,
    });
  };

  const runDecrypt = () =>
    decrypt.run({
      key_hex: keyHex,
      ciphertext_hex: cipherHex,
    });

  return (
    <PanelCard
      title="HMAC-Based CCA Encryption"
      formula={"C=\\mathrm{Enc}_{k_{enc}}(m)\\|\\mathrm{HMAC}_{k_{mac}}(\\mathrm{Enc}_{k_{enc}}(m))"}
      desc="PA10 upgrades the earlier CCA composition by authenticating ciphertexts with the new DLP-hash-backed HMAC."
      fullWidth
      inputContent={
        <>
          <Field label="Master key" hint="One 16-byte key is hashed into independent encryption and HMAC subkeys.">
            <input value={keyHex} onChange={(e) => setKeyHex(e.target.value)} className="input mono" />
          </Field>
          <Field label="Plaintext">
            <textarea
              value={message}
              onChange={(e) => setMessage(e.target.value)}
              className="input"
              rows={4}
              style={{ resize: "vertical", minHeight: 96 }}
            />
          </Field>
          <div style={{ display: "flex", gap: 10, flexWrap: "wrap" }}>
            <button className="btn-primary" onClick={runEncrypt} disabled={encrypt.loading}>
              {encrypt.loading ? <><Spinner /> Encrypting...</> : "Encrypt + Tag"}
            </button>
            <button className="btn-secondary" onClick={runDecrypt} disabled={decrypt.loading || !cipherHex.trim()}>
              {decrypt.loading ? <><Spinner /> Decrypting...</> : "Decrypt Bundle"}
            </button>
          </div>
          <Field label="Ciphertext bundle" hint="You can edit this hex to try tampering before decrypting.">
            <textarea
              value={cipherHex}
              onChange={(e) => setCipherHex(e.target.value)}
              className="input mono"
              rows={5}
              style={{ resize: "vertical", minHeight: 112 }}
            />
          </Field>
        </>
      }
      outputContent={
        <div className="result-area">
          {(encrypt.loading || decrypt.loading) && (
            <div className="result-loading" style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Spinner />
              <span>{encrypt.loading ? "Encrypting..." : "Decrypting..."}</span>
            </div>
          )}
          {!encrypt.loading && !decrypt.loading && (encrypt.error || decrypt.error) && (
            <div className="result-error">
              <span className="result-error-label">Error</span>
              <pre>{encrypt.error || decrypt.error}</pre>
            </div>
          )}
          {!encrypt.loading && !decrypt.loading && !encrypt.error && !decrypt.error && (
            <EncryptDecryptResult encryptData={encrypt.data} decryptData={decrypt.data} />
          )}
        </div>
      }
    />
  );
}

export function PA10SecurityPanel() {
  const protection = useAsync(api.pa10Protection);
  const cca = useAsync(api.pa10CcaGame);
  const [trials, setTrials] = useState(100);

  return (
    <PanelCard
      title="CCA Security Demo"
      formula={"\\Pr[\\text{tampered ciphertext accepted}] \\approx 0"}
      desc="These demos show the practical security gain from authenticating ciphertexts before decryption."
      fullWidth
      inputContent={
        <>
          <button className="btn-primary" onClick={() => protection.run({})} disabled={protection.loading}>
            {protection.loading ? <><Spinner /> Running demo...</> : "Run Tamper Demo"}
          </button>
          <Field label="CCA trials" hint="How many independent tamper attempts to sample.">
            <input
              type="number"
              min={10}
              max={2000}
              value={trials}
              onChange={(e) => setTrials(e.target.value)}
              className="input"
              style={{ width: 120 }}
            />
          </Field>
          <button className="btn-secondary" onClick={() => cca.run({ trials: Number(trials) })} disabled={cca.loading}>
            {cca.loading ? <><Spinner /> Simulating...</> : "Run CCA Game"}
          </button>
        </>
      }
      outputContent={
        <div className="result-area">
          {(protection.loading || cca.loading) && (
            <div className="result-loading" style={{ display: "flex", alignItems: "center", gap: 8 }}>
              <Spinner />
              <span>{protection.loading ? "Running tamper demo..." : "Running CCA experiment..."}</span>
            </div>
          )}
          {!protection.loading && !cca.loading && (protection.error || cca.error) && (
            <div className="result-error">
              <span className="result-error-label">Error</span>
              <pre>{protection.error || cca.error}</pre>
            </div>
          )}
          {!protection.loading && !cca.loading && !protection.error && !cca.error && !protection.data && !cca.data && (
            <div className="result-empty"><span>Results will appear here</span></div>
          )}
          {protection.data && (
            <div className="result-structured" style={{ marginBottom: cca.data ? 16 : 0 }}>
              <div className="result-row" style={{ flexWrap: "wrap", gap: 8 }}>
                <Badge variant={protection.data.etm_rejected ? "pass" : "fail"}>
                  {protection.data.etm_rejected ? "Tampering Rejected" : "Tampering Accepted"}
                </Badge>
              </div>
              <div className="result-field">
                <span className="result-field-label">Bare encryption after tampering</span>
                <span className="result-val">{protection.data.bare_tampered_plaintext}</span>
              </div>
              <div className="result-field">
                <span className="result-field-label">Protected bundle</span>
                <code className="hex-output">{protection.data.etm_ciphertext_hex}</code>
              </div>
              <div className="result-field">
                <span className="result-field-label">Security insight</span>
                <span className="result-desc">{protection.data.insight}</span>
              </div>
            </div>
          )}
          {cca.data && (
            <div className="result-structured">
              <div className="result-row" style={{ flexWrap: "wrap", gap: 8 }}>
                <Badge variant={cca.data.cca_protected ? "pass" : "fail"}>
                  {cca.data.cca_protected ? "CCA protection observed" : "Warning"}
                </Badge>
                <Badge variant="info">{cca.data.trials} trials</Badge>
              </div>
              <div className="result-field">
                <span className="result-field-label">Tamper rejection rate</span>
                <span className="result-val">{(cca.data.tamper_rejection_rate * 100).toFixed(1)}%</span>
              </div>
              <div className="result-field">
                <span className="result-field-label">Experiment label</span>
                <span className="result-desc">{cca.data.experiment}</span>
              </div>
            </div>
          )}
        </div>
      }
    />
  );
}
