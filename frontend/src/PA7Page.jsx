import { CliqueBanner, PageHeader } from "./shared";
import { PA7CollisionPanel, PA7HashPanel } from "./panels";

const TABS = [
  { key: "mdhash", label: "Chain Viewer" },
  { key: "collision", label: "Collision Demo" },
];

export function PA7Page({ tab, onTabChange, onBack }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      <div className="l2-topbar">
        <button className="breadcrumb-btn" onClick={onBack}>← Explorer Home</button>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current">PA #7 — Merkle-Damgard Transform</span>
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

        {tab === "mdhash" && <PA7HashPanel />}
        {tab === "collision" && <PA7CollisionPanel />}
      </main>
    </div>
  );
}
