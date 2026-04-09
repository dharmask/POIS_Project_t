import React from "react";
import { CliqueBanner, PageHeader } from "./shared";
import { PA10CCAPanel, PA10HMACPanel, PA10SecurityPanel } from "./PA10Panels";

const TABS = [
  { key: "hmac", label: "HMAC" },
  { key: "cca", label: "Encrypt + Decrypt" },
  { key: "security", label: "Security Demo" },
];

export function PA10Page({ tab, onTabChange, onBack }) {
  return (
    <div style={{ display: "flex", flexDirection: "column", flex: 1 }}>
      <div className="l2-topbar">
        <button className="breadcrumb-btn" onClick={onBack}>Explorer Home</button>
        <span className="breadcrumb-sep">/</span>
        <span className="breadcrumb-current">PA #10 - HMAC and HMAC-Based CCA Encryption</span>
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

        {tab === "hmac" && <PA10HMACPanel />}
        {tab === "cca" && <PA10CCAPanel />}
        {tab === "security" && <PA10SecurityPanel />}
      </main>
    </div>
  );
}
