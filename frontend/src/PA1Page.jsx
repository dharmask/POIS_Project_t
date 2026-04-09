import { CliqueBanner, PageHeader } from "./shared";
import { OWFPanel, PRGPanel, NISTPanel, OWFHardnessPanel, OWFFromPRGPanel } from "./panels";

const TABS = [
  { key: "owf",       label: "One-Way Function" },
  { key: "owf-hard",  label: "OWF Hardness" },
  { key: "prg",       label: "Pseudorandom Generator" },
  { key: "owf-prg",   label: "PRG → OWF (Backward)" },
  { key: "nist",      label: "NIST SP 800-22" },
];

export function PA1Page({ tab, onTabChange, foundation, onBack }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      {/* Breadcrumb / topbar */}
      <div className="l2-topbar">
        <button className="breadcrumb-btn" onClick={onBack}>
          ← Explorer Home
        </button>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current">PA #1 — OWF + PRG</span>
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
        {tab === "owf"      && <OWFPanel        foundation={foundation} />}
        {tab === "owf-hard" && <OWFHardnessPanel foundation={foundation} />}
        {tab === "prg"      && <PRGPanel         foundation={foundation} />}
        {tab === "owf-prg"  && <OWFFromPRGPanel  foundation={foundation} />}
        {tab === "nist"     && <NISTPanel         foundation={foundation} />}
      </main>
    </div>
  );
}
