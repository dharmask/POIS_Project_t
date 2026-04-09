import { Suspense, lazy, useEffect, useState } from "react";
import "./App.css";

const ExplorerHome = lazy(() => import("./ExplorerHome").then((m) => ({ default: m.ExplorerHome })));
const PA0Page = lazy(() => import("./PA0Page").then((m) => ({ default: m.PA0Page })));
const PA1Page = lazy(() => import("./PA1Page").then((m) => ({ default: m.PA1Page })));
const PA2Page = lazy(() => import("./PA2Page").then((m) => ({ default: m.PA2Page })));
const PA3Page = lazy(() => import("./PA3Page").then((m) => ({ default: m.PA3Page })));
const PA4Page = lazy(() => import("./PA4Page").then((m) => ({ default: m.PA4Page })));
const PA5Page = lazy(() => import("./PA5Page").then((m) => ({ default: m.PA5Page })));
const PA6Page = lazy(() => import("./PA6Page").then((m) => ({ default: m.PA6Page })));
const PA7Page = lazy(() => import("./PA7Page").then((m) => ({ default: m.PA7Page })));
const PA8Page = lazy(() => import("./PA8Page").then((m) => ({ default: m.PA8Page })));
const PA9Page = lazy(() => import("./PA9Page").then((m) => ({ default: m.PA9Page })));
const PA10Page = lazy(() => import("./PA10Page").then((m) => ({ default: m.PA10Page })));

// ─── Navigation config ────────────────────────────────────────────────────────
const NAV = [
  {
    pa: "PA #1", label: "OWF + PRG", key: "pa1",
    items: [
      { key: "owf",  label: "One-Way Function",       icon: "ƒ",  tab: "owf"  },
      { key: "prg",  label: "Pseudorandom Generator", icon: "G",  tab: "prg"  },
      { key: "nist", label: "NIST SP 800-22 Tests",   icon: "≈",  tab: "nist" },
    ],
  },
  {
    pa: "PA #2", label: "PRF (GGM Tree)", key: "pa2",
    items: [
      { key: "ggmtree", label: "GGM Tree Visualiser",  icon: "🌲", tab: "ggmtree" },
      { key: "prf",     label: "Pseudorandom Function", icon: "F",  tab: "prf"     },
      { key: "prgprf",  label: "PRG from PRF",          icon: "⇒", tab: "prgprf"  },
      { key: "game",    label: "Distinguishing Game",   icon: "⚔", tab: "game"    },
    ],
  },
  {
    pa: "PA #3", label: "CPA Encryption", key: "pa3",
    items: [
      { key: "enc",     label: "Encrypt",  icon: "E",  tab: "enc"     },
      { key: "dec",     label: "Decrypt",  icon: "D",  tab: "dec"     },
      { key: "cpagame", label: "CPA Game", icon: "⚔", tab: "cpagame" },
    ],
  },
  {
    pa: "PA #4", label: "Modes of Operation", key: "pa4",
    items: [
      { key: "prp",    label: "PRP (AES)",     icon: "P",  tab: "prp"    },
      { key: "ecb",    label: "ECB Mode",       icon: "E",  tab: "ecb"    },
      { key: "cbc",    label: "CBC Mode",       icon: "C",  tab: "cbc"    },
      { key: "ctr",    label: "CTR Mode",       icon: "⊕", tab: "ctr"    },
      { key: "oracle", label: "Padding Oracle", icon: "⚠", tab: "oracle" },
    ],
  },
  {
    pa: "PA #5", label: "MACs", key: "pa5",
    items: [
      { key: "mac",    label: "MAC",              icon: "T",  tab: "mac"    },
      { key: "lenext", label: "Length Extension",  icon: "↗", tab: "lenext" },
      { key: "eufcma", label: "EUF-CMA Game",      icon: "⚔", tab: "eufcma" },
    ],
  },
  {
    pa: "Part III", label: "Public-Key (RSA / DH)", key: "pa6",
    items: [
      { key: "rsa",     label: "RSA Encrypt",      icon: "R", tab: "rsa"     },
      { key: "rsasign", label: "RSA Signatures",   icon: "S", tab: "rsasign" },
      { key: "rsacpa",  label: "RSA CPA Demo",     icon: "!", tab: "rsacpa"  },
      { key: "dh",      label: "DH Exchange",       icon: "D", tab: "dh"      },
      { key: "mitm",    label: "MITM Attack",        icon: "M", tab: "mitm"    },
      { key: "authdh",  label: "Authenticated DH",  icon: "A", tab: "authdh"  },
    ],
  },
  {
    pa: "PA #7", label: "Merkle-Damgard", key: "pa7",
    items: [
      { key: "mdhash", label: "Chain Viewer", icon: "H", tab: "mdhash" },
      { key: "collision", label: "Collision Demo", icon: "C", tab: "collision" },
    ],
  },
  {
    pa: "PA #8", label: "DLP-Based CRHF", key: "pa8",
    items: [
      { key: "dlphash", label: "DLP Hash", icon: "H", tab: "dlphash" },
      { key: "hunt", label: "Collision Hunt", icon: "C", tab: "hunt" },
    ],
  },
  {
    pa: "PA #9", label: "Birthday Attack", key: "pa9",
    items: [
      { key: "live", label: "Live Demo", icon: "R", tab: "live" },
      { key: "compare", label: "Compare Algorithms", icon: "=", tab: "compare" },
      { key: "dlpattack", label: "Attack DLP Hash", icon: "D", tab: "dlpattack" },
      { key: "curve", label: "Birthday Curve", icon: "P", tab: "curve" },
      { key: "context", label: "MD5 / SHA-1 Context", icon: "T", tab: "context" },
    ],
  },
  {
    pa: "PA #10", label: "HMAC + CCA", key: "pa10",
    items: [
      { key: "hmac", label: "HMAC", icon: "H", tab: "hmac" },
      { key: "cca", label: "Encrypt + Decrypt", icon: "C", tab: "cca" },
      { key: "security", label: "Security Demo", icon: "S", tab: "security" },
    ],
  },
];

// ─── Hash routing helpers ─────────────────────────────────────────────────────
const DEFAULT_TABS = {
  pa1: "owf", pa2: "ggmtree", pa3: "enc",
  pa4: "prp", pa5: "mac", pa6: "rsa", pa7: "mdhash", pa8: "dlphash", pa9: "live", pa10: "hmac",
};

function parseHash() {
  // Format: #view  or  #view/tab
  const raw = window.location.hash.replace(/^#/, "") || "home";
  const [view, tab] = raw.split("/");
  return { view, tab: tab || null };
}

function pushHash(view, tab) {
  const hash = tab ? `#${view}/${tab}` : `#${view}`;
  if (window.location.hash !== hash) {
    window.history.pushState(null, "", hash);
  }
}

// ─── Sidebar ──────────────────────────────────────────────────────────────────
function Sidebar({ view, pa1Tab, pa2Tab, pa3Tab, pa4Tab, pa5Tab, pa6Tab, pa7Tab, pa8Tab, pa9Tab, pa10Tab, navigate }) {
  const activeItemKey =
    view === "pa1" ? pa1Tab :
    view === "pa2" ? pa2Tab :
    view === "pa3" ? pa3Tab :
    view === "pa4" ? pa4Tab :
    view === "pa5" ? pa5Tab :
    view === "pa6" ? pa6Tab :
    view === "pa7" ? pa7Tab :
    view === "pa8" ? pa8Tab :
    view === "pa10" ? pa10Tab :
    view === "pa9" ? pa9Tab :
    null;

  return (
    <aside className="sidebar">
      <div className="sidebar-brand">
        <div className="brand-icon">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M12 2L4 6v6c0 4.418 3.357 8.169 8 9.93C16.643 20.169 20 16.418 20 12V6L12 2z" />
            <path d="M9 12l2 2 4-4" strokeLinecap="round" strokeLinejoin="round" />
          </svg>
        </div>
        <div>
          <div className="brand-course">CS8.401</div>
          <div className="brand-title">Minicrypt Explorer</div>
        </div>
      </div>

      <nav className="sidebar-nav">
        <button
          className={`nav-home-item${view === "home" ? " nav-home-active" : ""}`}
          onClick={() => navigate("home")}
        >
          <span style={{ fontSize: 15 }}>🏠</span>
          <span>Home</span>
        </button>

        <button
          className={`nav-home-item${view === "pa0" ? " nav-home-active" : ""}`}
          onClick={() => navigate("pa0")}
        >
          <span style={{ fontSize: 15 }}>⚡</span>
          <span>PA #0 — Clique Explorer</span>
        </button>

        {NAV.map(group => (
          <div key={group.key} className={`nav-group${group.locked ? " nav-group-locked" : ""}`}>
            <div className="nav-group-header">
              <span className="nav-pa-badge">{group.pa}</span>
              <span className="nav-group-label">{group.label}</span>
              {group.locked && <span className="nav-locked-chip">Soon</span>}
            </div>
            {!group.locked && group.items.map(item => {
              const isActive = activeItemKey === item.tab && view === group.key;
              return (
                <button
                  key={item.key}
                  className={`nav-item${isActive ? " nav-item-active" : ""}`}
                  onClick={() => navigate(group.key, item.tab)}
                >
                  <span className="nav-item-icon">{item.icon}</span>
                  <span>{item.label}</span>
                </button>
              );
            })}
          </div>
        ))}
      </nav>

      <div className="sidebar-footer">
        <a href="http://localhost:8000/docs" target="_blank" rel="noreferrer" className="api-docs-link">
          <svg viewBox="0 0 16 16" fill="currentColor" width="11" height="11">
            <path d="M2 2h5v1.5H3.5v9h9V9H14v5H2V2zm7 0h4v4h-1.5V4.06L7.53 8l-1.06-1.06L10.44 3H8V2z"/>
          </svg>
          API Docs ↗
        </a>
      </div>
    </aside>
  );
}

// ─── App root ─────────────────────────────────────────────────────────────────
export default function App() {
  // Initialise from URL hash so refresh restores position
  const initHash = parseHash();
  const [view,       setView]       = useState(initHash.view);
  const [pa1Tab,     setPA1Tab]     = useState(initHash.view === "pa1" && initHash.tab ? initHash.tab : DEFAULT_TABS.pa1);
  const [pa2Tab,     setPA2Tab]     = useState(initHash.view === "pa2" && initHash.tab ? initHash.tab : DEFAULT_TABS.pa2);
  const [pa3Tab,     setPA3Tab]     = useState(initHash.view === "pa3" && initHash.tab ? initHash.tab : DEFAULT_TABS.pa3);
  const [pa4Tab,     setPA4Tab]     = useState(initHash.view === "pa4" && initHash.tab ? initHash.tab : DEFAULT_TABS.pa4);
  const [pa5Tab,     setPA5Tab]     = useState(initHash.view === "pa5" && initHash.tab ? initHash.tab : DEFAULT_TABS.pa5);
  const [pa6Tab,     setPA6Tab]     = useState(initHash.view === "pa6" && initHash.tab ? initHash.tab : DEFAULT_TABS.pa6);
  const [pa7Tab,     setPA7Tab]     = useState(initHash.view === "pa7" && initHash.tab ? initHash.tab : DEFAULT_TABS.pa7);
  const [pa8Tab,     setPA8Tab]     = useState(initHash.view === "pa8" && initHash.tab ? initHash.tab : DEFAULT_TABS.pa8);
  const [pa9Tab,     setPA9Tab]     = useState(initHash.view === "pa9" && initHash.tab ? initHash.tab : DEFAULT_TABS.pa9);
  const [pa10Tab,    setPA10Tab]    = useState(initHash.view === "pa10" && initHash.tab ? initHash.tab : DEFAULT_TABS.pa10);
  const [foundation, setFoundation] = useState("aes");

  // Sync state → hash whenever view/tab changes
  const navigate = (v, tab) => {
    const resolvedTab = tab || DEFAULT_TABS[v] || null;
    setView(v);
    if (v === "pa1" && tab) setPA1Tab(tab);
    if (v === "pa2" && tab) setPA2Tab(tab);
    if (v === "pa3" && tab) setPA3Tab(tab);
    if (v === "pa4" && tab) setPA4Tab(tab);
    if (v === "pa5" && tab) setPA5Tab(tab);
    if (v === "pa6" && tab) setPA6Tab(tab);
    if (v === "pa7" && tab) setPA7Tab(tab);
    if (v === "pa8" && tab) setPA8Tab(tab);
    if (v === "pa9" && tab) setPA9Tab(tab);
    if (v === "pa10" && tab) setPA10Tab(tab);
    pushHash(v, resolvedTab);
  };

  // Handle browser back/forward buttons
  useEffect(() => {
    const onPop = () => {
      const { view: v, tab } = parseHash();
      setView(v);
      if (v === "pa1" && tab) setPA1Tab(tab);
      if (v === "pa2" && tab) setPA2Tab(tab);
      if (v === "pa3" && tab) setPA3Tab(tab);
      if (v === "pa4" && tab) setPA4Tab(tab);
      if (v === "pa5" && tab) setPA5Tab(tab);
      if (v === "pa6" && tab) setPA6Tab(tab);
      if (v === "pa7" && tab) setPA7Tab(tab);
      if (v === "pa8" && tab) setPA8Tab(tab);
      if (v === "pa9" && tab) setPA9Tab(tab);
      if (v === "pa10" && tab) setPA10Tab(tab);
    };
    window.addEventListener("popstate", onPop);
    return () => window.removeEventListener("popstate", onPop);
  }, []);

  // Write initial hash if the URL is bare (first visit)
  useEffect(() => {
    if (!window.location.hash) {
      pushHash(view, DEFAULT_TABS[view] || null);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const currentPA2Tab = pa2Tab;

  return (
    <div className="app-shell">
      <Sidebar
        view={view}
        pa1Tab={pa1Tab}
        pa2Tab={currentPA2Tab}
        pa3Tab={pa3Tab}
        pa4Tab={pa4Tab}
        pa5Tab={pa5Tab}
        pa6Tab={pa6Tab}
        pa7Tab={pa7Tab}
        pa8Tab={pa8Tab}
        pa9Tab={pa9Tab}
        pa10Tab={pa10Tab}
        navigate={navigate}
      />
      <Suspense fallback={<div className="main-area"><div className="result-area result-loading"><span className="spinner" aria-label="Loading" /><span>Loading page...</span></div></div>}>
        <div className="main-area">
          {view === "home" && <ExplorerHome onNavigate={navigate} />}
          {view === "pa0" && (
            <PA0Page
              foundation={foundation}
              onFoundationChange={setFoundation}
              onBack={() => navigate("home")}
              onNavigate={navigate}
            />
          )}
          {view === "pa1" && (
            <PA1Page
              tab={pa1Tab}
              onTabChange={t => { setPA1Tab(t); pushHash("pa1", t); }}
              foundation={foundation}
              onBack={() => navigate("home")}
            />
          )}
          {view === "pa2" && (
            <PA2Page
              tab={currentPA2Tab}
              onTabChange={t => { setPA2Tab(t); pushHash("pa2", t); }}
              foundation={foundation}
              onBack={() => navigate("home")}
            />
          )}
          {view === "pa3" && (
            <PA3Page
              tab={pa3Tab}
              onTabChange={t => { setPA3Tab(t); pushHash("pa3", t); }}
              onBack={() => navigate("home")}
            />
          )}
          {view === "pa4" && (
            <PA4Page
              tab={pa4Tab}
              onTabChange={t => { setPA4Tab(t); pushHash("pa4", t); }}
              onBack={() => navigate("home")}
            />
          )}
          {view === "pa5" && (
            <PA5Page
              tab={pa5Tab}
              onTabChange={t => { setPA5Tab(t); pushHash("pa5", t); }}
              onBack={() => navigate("home")}
            />
          )}
          {view === "pa6" && (
            <PA6Page
              tab={pa6Tab}
              onTabChange={t => { setPA6Tab(t); pushHash("pa6", t); }}
              onBack={() => navigate("home")}
            />
          )}
          {view === "pa7" && (
            <PA7Page
              tab={pa7Tab}
              onTabChange={t => { setPA7Tab(t); pushHash("pa7", t); }}
              onBack={() => navigate("home")}
            />
          )}
          {view === "pa8" && (
            <PA8Page
              tab={pa8Tab}
              onTabChange={t => { setPA8Tab(t); pushHash("pa8", t); }}
              onBack={() => navigate("home")}
            />
          )}
          {view === "pa9" && (
            <PA9Page
              tab={pa9Tab}
              onTabChange={t => { setPA9Tab(t); pushHash("pa9", t); }}
              onBack={() => navigate("home")}
            />
          )}
          {view === "pa10" && (
            <PA10Page
              tab={pa10Tab}
              onTabChange={t => { setPA10Tab(t); pushHash("pa10", t); }}
              onBack={() => navigate("home")}
            />
          )}
        </div>
      </Suspense>
    </div>
  );
}
