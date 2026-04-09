import { CliqueBanner, PageHeader } from "./shared";
import { MACPanel, LengthExtPanel, EUFCMAPanel } from "./panels";

const TABS = [
  { key: "mac", label: "MAC" },
  { key: "lenext", label: "Length Extension" },
  { key: "eufcma", label: "EUF-CMA Game" },
];

export function PA5Page({ tab, onTabChange, onBack }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      <div className="l2-topbar">
        <button className="breadcrumb-btn" onClick={onBack}>← Explorer Home</button>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current">PA #5 — Message Authentication Codes</span>
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

        {tab === "mac" && <MACPanel />}
        {tab === "lenext" && <LengthExtPanel />}
        {tab === "eufcma" && <EUFCMAPanel />}
      </main>
    </div>
  );
}
