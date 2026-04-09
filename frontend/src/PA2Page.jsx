import { CliqueBanner, PageHeader } from "./shared";
import { PRFPanel, PRGFromPRFPanel, DistGamePanel, GGMTreePanel } from "./panels";

const TABS = [
  { key: "ggmtree", label: "GGM Tree Visualiser" },
  { key: "prf",     label: "Pseudorandom Function" },
  { key: "prgprf",  label: "PRG from PRF" },
  { key: "game",    label: "Distinguishing Game" },
];

export function PA2Page({ tab, onTabChange, onBack }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      {/* Breadcrumb / topbar */}
      <div className="l2-topbar">
        <button className="breadcrumb-btn" onClick={onBack}>
          ← Explorer Home
        </button>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current">PA #2 — PRF + GGM Tree</span>
      </div>

      {/* Clique banner */}
      <CliqueBanner page={tab} />

      <main className="main-content">
        {/* Page header */}
        <PageHeader pageKey={tab} />

        {/* Tab nav */}
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

        {/* Active panel */}
        {tab === "ggmtree" && <GGMTreePanel />}
        {tab === "prf"     && <PRFPanel />}
        {tab === "prgprf"  && <PRGFromPRFPanel />}
        {tab === "game"    && <DistGamePanel />}
      </main>
    </div>
  );
}
