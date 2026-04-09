import { CliqueBanner, PageHeader } from "./shared";
import { PRPPanel, ECBPanel, CBCPanel, CTRPanel, PaddingOraclePanel } from "./panels";

const TABS = [
  { key: "prp", label: "PRP (AES)" },
  { key: "ecb", label: "ECB Mode" },
  { key: "cbc", label: "CBC Mode" },
  { key: "ctr", label: "CTR Mode" },
  { key: "oracle", label: "Padding Oracle" },
];

export function PA4Page({ tab, onTabChange, onBack }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      <div className="l2-topbar">
        <button className="breadcrumb-btn" onClick={onBack}>← Explorer Home</button>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current">PA #4 — Modes of Operation</span>
      </div>

      <CliqueBanner page={tab} />

      <main className="main-content">
        <PageHeader pageKey={tab} />

        <div className="tab-nav">
          {TABS.map(t => (
            <button
              key={t.key}
              className={`tab-btn${tab === t.key ? " tab-btn-active" : ""}`}
              onClick={() => onTabChange(t.key)}
            >
              {t.label}
            </button>
          ))}
        </div>

        {tab === "prp" && <PRPPanel />}
        {tab === "ecb" && <ECBPanel />}
        {tab === "cbc" && <CBCPanel />}
        {tab === "ctr" && <CTRPanel />}
        {tab === "oracle" && <PaddingOraclePanel />}
      </main>
    </div>
  );
}
