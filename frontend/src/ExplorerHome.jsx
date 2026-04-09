import { useState } from "react";

const PARTS = [
  {
    key: "part0",
    part: "PA #0",
    title: "Minicrypt Clique Web Explorer",
    subtitle: "Foundation toggle · Black-box reductions · Bidirectional routing · Live hex demos",
    pas: [
      { pa: "PA #0", title: "Minicrypt Clique Web Explorer", desc: "Two-column React app: Column 1 builds source primitive from AES/DLP foundation, Column 2 applies reduction A->B using only black-box access. Includes proof sketch accordion and live values.", link: "pa0" },
    ],
  },
  {
    key: "part1",
    part: "Part I",
    title: "Symmetric Key Cryptography",
    subtitle: "One-Way Functions, PRGs, PRFs, Encryption, and MACs - the Minicrypt Clique",
    pas: [
      { pa: "PA #1", title: "One-Way Functions & Pseudorandom Generators", desc: "DLP/AES-based OWFs, GL PRG via HILL hard-core bit, NIST SP 800-22 statistical tests", link: "pa1" },
      { pa: "PA #2", title: "Pseudorandom Functions via GGM Tree", desc: "PRF from PRG using GGM binary tree, AES plug-in alternative, distinguishing game demo", link: "pa2" },
      { pa: "PA #3", title: "CPA-Secure Symmetric Encryption", desc: "Enc-then-PRF scheme C=(r, Fk(r) xor m), IND-CPA game simulation, broken deterministic variant", link: "pa3" },
      { pa: "PA #4", title: "Modes of Operation", desc: "AES PRP, ECB / CBC / CTR modes, IV-reuse attack in CBC, keystream-reuse in OFB demo", link: "pa4" },
      { pa: "PA #5", title: "Message Authentication Codes", desc: "PRF-MAC, CBC-MAC, EUF-CMA forgery game, and the setup for why HMAC is introduced later in PA10", link: "pa5" },
    ],
  },
  {
    key: "part2",
    part: "Part II",
    title: "Hashing and Data Integrity",
    subtitle: "Merkle-Damgard, DLP-Based CRHF, Birthday Attacks, and HMAC",
    pas: [
      { pa: "PA #7", title: "Merkle-Damgard Transform", desc: "Generic MD framework, MD-strengthening padding, chain tracing, and collision propagation demo", link: "pa7" },
      { pa: "PA #8", title: "DLP-Based Collision-Resistant Hash", desc: "DLP compression over a safe-prime subgroup, full MD hash, truncation, and a 16-bit collision hunt", link: "pa8" },
      { pa: "PA #9", title: "Birthday Attack (Collision Finding)", desc: "Naive and Floyd collision search, truncated DLP-hash attack, empirical birthday curves, and a live attack demo", link: "pa9" },
      { pa: "PA #10", title: "HMAC and HMAC-Based CCA Encryption", desc: "HMAC built from the PA8 DLP hash, Encrypt-then-HMAC, and tamper-rejection demos", link: "pa10" },
    ],
  },
  {
    key: "part3",
    part: "Part III",
    title: "Public-Key Cryptography",
    subtitle: "Cryptomania - DH, RSA, ElGamal, Digital Signatures, and CCA-Secure PKC",
    pas: [
      { pa: "Part III", title: "Public-Key (RSA / DH / MITM / Auth-DH)", desc: "RSA encrypt & sign, Diffie-Hellman exchange, Man-in-the-Middle attack, Authenticated DH", link: "pa6" },
    ],
  },
  {
    key: "part4",
    part: "Part IV",
    title: "Secure Multi-Party Computation",
    subtitle: "Oblivious Transfer, Secure Gates, and All 2-Party MPC via Yao/GMW",
    pas: [],
    locked: true,
  },
];

function PAOverview({ onNavigate }) {
  const [openParts, setOpenParts] = useState({ part0: true, part1: true, part2: true, part3: true });
  const toggle = (key) => setOpenParts(prev => ({ ...prev, [key]: !prev[key] }));

  return (
    <div className="pa-overview">
      <div className="pa-overview-title">Assignments</div>
      <div className="pa-overview-list">
        {PARTS.map(part => (
          <div
            key={part.key}
            className={`pa-overview-section${part.locked ? " pa-overview-locked" : ""}${openParts[part.key] && !part.locked ? " pa-overview-section-open" : ""}`}
          >
            <button
              className="pa-overview-header"
              onClick={() => !part.locked && toggle(part.key)}
            >
              <div className="pa-overview-header-left">
                <span className="pa-overview-part-badge">{part.part}</span>
                <div className="pa-overview-header-text">
                  <div className="pa-overview-part-title">{part.title}</div>
                  <div className="pa-overview-part-subtitle">{part.subtitle}</div>
                </div>
              </div>
              {part.locked
                ? <span className="pa-overview-soon">Soon</span>
                : <span className={`pa-overview-chevron${openParts[part.key] ? " pa-overview-chevron-open" : ""}`}>›</span>
              }
            </button>
            {openParts[part.key] && !part.locked && part.pas.length > 0 && (
              <div className="pa-overview-items">
                {part.pas.map(pa => (
                  <button
                    key={pa.pa}
                    className="pa-overview-item"
                    onClick={() => onNavigate?.(pa.link)}
                  >
                    <div className="pa-overview-item-left">
                      <span className="pa-overview-item-pa">{pa.pa}</span>
                      <div className="pa-overview-item-text">
                        <div className="pa-overview-item-title">{pa.title}</div>
                        <div className="pa-overview-item-desc">{pa.desc}</div>
                      </div>
                    </div>
                    <span className="pa-overview-item-arrow">›</span>
                  </button>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  );
}

export function ExplorerHome({ onNavigate }) {
  return (
    <div className="explorer-wrap">
      <div className="explorer-hero">
        <div className="explorer-course-chip">CS8.401 - Principles of Information Security</div>
        <h1 className="explorer-title">Minicrypt Explorer</h1>
        <p className="explorer-tagline">
          Cryptographic Primitives - from One-Way Functions to Secure Multi-Party Computation.
          Select an assignment below to open its interactive demo.
        </p>
      </div>

      <hr style={{ border: "none", borderTop: "1px solid var(--border-1)", margin: "0 0 28px" }} />

      <PAOverview onNavigate={onNavigate} />
    </div>
  );
}
