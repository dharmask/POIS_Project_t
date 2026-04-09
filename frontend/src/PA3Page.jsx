import { CliqueBanner, PageHeader } from "./shared";
import { PA3EncryptPanel, PA3DecryptPanel, PA3CPAGamePanel } from "./panels";

const TABS = [
  { key: "enc", label: "Encrypt" },
  { key: "dec", label: "Decrypt" },
  { key: "cpagame", label: "CPA Game" },
];

export function PA3Page({ tab, onTabChange, onBack }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      <div className="l2-topbar">
        <button className="breadcrumb-btn" onClick={onBack}>← Explorer Home</button>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current">PA #3 — CPA-Secure Encryption</span>
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

        {tab === "enc" && <PA3EncryptPanel />}
        {tab === "dec" && <PA3DecryptPanel />}
        {tab === "cpagame" && <PA3CPAGamePanel />}
      </main>
    </div>
  );
}
