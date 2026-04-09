import { CliqueBanner, PageHeader } from "./shared";
import { PA8CollisionPanel, PA8HashPanel } from "./panels";

const TABS = [
  { key: "dlphash", label: "DLP Hash" },
  { key: "hunt", label: "Collision Hunt" },
];

export function PA8Page({ tab, onTabChange, onBack }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      <div className="l2-topbar">
        <button className="breadcrumb-btn" onClick={onBack}>Explorer Home</button>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current">PA #8 - DLP-Based Collision-Resistant Hash</span>
      </div>

      <CliqueBanner page={tab} />

      <main className="main-content">
        <PageHeader pageKey={tab} />

        <div className="tab-nav">
          {TABS.map((entry) => (
            <button
              key={entry.key}
              className={`tab-btn${tab === entry.key ? " tab-btn-active" : ""}`}
              onClick={() => onTabChange(entry.key)}
            >
              {entry.label}
            </button>
          ))}
        </div>

        {tab === "dlphash" && <PA8HashPanel />}
        {tab === "hunt" && <PA8CollisionPanel />}
      </main>
    </div>
  );
}
