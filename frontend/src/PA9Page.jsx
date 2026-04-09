import React from "react";
import { CliqueBanner, PageHeader } from "./shared";
import {
  PA9ComparePanel,
  PA9ContextPanel,
  PA9CurvePanel,
  PA9DlpAttackPanel,
  PA9LiveDemoPanel,
} from "./PA9Panels";

const TABS = [
  { key: "live", label: "Live Demo" },
  { key: "compare", label: "Compare" },
  { key: "dlpattack", label: "DLP Attack" },
  { key: "curve", label: "Birthday Curve" },
  { key: "context", label: "MD5 / SHA-1" },
];

export function PA9Page({ tab, onTabChange, onBack }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      <div className="l2-topbar">
        <button className="breadcrumb-btn" onClick={onBack}>Explorer Home</button>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current">PA #9 - Birthday Attack (Collision Finding)</span>
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

        {tab === "live" && <PA9LiveDemoPanel />}
        {tab === "compare" && <PA9ComparePanel />}
        {tab === "dlpattack" && <PA9DlpAttackPanel />}
        {tab === "curve" && <PA9CurvePanel />}
        {tab === "context" && <PA9ContextPanel />}
      </main>
    </div>
  );
}
