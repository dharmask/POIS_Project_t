import { CliqueBanner, PageHeader } from "./shared";
import { RSAPanel, RSASignPanel, RSACPAPanel, DHPanel, MITMPanel, AuthDHPanel } from "./panels";

const TABS = [
  { key: "rsa", label: "RSA Encrypt" },
  { key: "rsasign", label: "RSA Signatures" },
  { key: "rsacpa", label: "RSA CPA Demo" },
  { key: "dh", label: "DH Exchange" },
  { key: "mitm", label: "MITM Attack" },
  { key: "authdh", label: "Authenticated DH" },
];

export function PA6Page({ tab, onTabChange, onBack }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      <div className="l2-topbar">
        <button className="breadcrumb-btn" onClick={onBack}>← Explorer Home</button>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current">Part III — Public-Key (RSA / DH)</span>
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

        {tab === "rsa" && <RSAPanel />}
        {tab === "rsasign" && <RSASignPanel />}
        {tab === "rsacpa" && <RSACPAPanel />}
        {tab === "dh" && <DHPanel />}
        {tab === "mitm" && <MITMPanel />}
        {tab === "authdh" && <AuthDHPanel />}
      </main>
    </div>
  );
}
