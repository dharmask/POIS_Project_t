/**
 * routePlanner.test.js — PA#0: Route Planner Unit Tests
 *
 * Tests the core graph-based BFS routing engine independently of any UI.
 * These verify that:
 *   1. Forward single-hop routes are found correctly.
 *   2. Backward single-hop routes are found via the reverse graph.
 *   3. Multi-hop routes are composed correctly (BFS shortest path).
 *   4. Unsupported pairs return null (no path).
 *   5. getValidTargets returns direct neighbors only.
 *   6. getEffectiveReductionKey returns correct table keys.
 *   7. describeRoute renders a human-readable route string.
 */

import { describe, it, expect } from "vitest";
import {
  planRoute,
  getValidTargets,
  isDirectlySupported,
  isRouteSupported,
  getEffectiveReductionKey,
  describeRoute,
  CLIQUE_GRAPH,
  REVERSE_GRAPH,
} from "../routePlanner";

// ─── CLIQUE_GRAPH structure ────────────────────────────────────────────────────

describe("CLIQUE_GRAPH", () => {
  it("contains all expected forward edges", () => {
    expect(CLIQUE_GRAPH.owf).toContain("prg");
    expect(CLIQUE_GRAPH.owf).toContain("owp");
    expect(CLIQUE_GRAPH.prg).toContain("prf");
    expect(CLIQUE_GRAPH.prf).toContain("prg");
    expect(CLIQUE_GRAPH.prf).toContain("prp");
    expect(CLIQUE_GRAPH.prf).toContain("mac");
    expect(CLIQUE_GRAPH.prp).toContain("mac");
    expect(CLIQUE_GRAPH.crhf).toContain("hmac");
    expect(CLIQUE_GRAPH.hmac).toContain("mac");
  });

  it("mac has no forward edges (terminal node)", () => {
    expect(CLIQUE_GRAPH.mac).toEqual([]);
  });
});

describe("REVERSE_GRAPH", () => {
  it("prg can reverse to owf", () => {
    expect(REVERSE_GRAPH.prg).toContain("owf");
  });

  it("prf can reverse to prg", () => {
    expect(REVERSE_GRAPH.prf).toContain("prg");
  });

  it("mac can reverse to prf and prp", () => {
    expect(REVERSE_GRAPH.mac).toContain("prf");
    expect(REVERSE_GRAPH.mac).toContain("prp");
  });
});

// ─── planRoute ─────────────────────────────────────────────────────────────────

describe("planRoute — forward", () => {
  it("direct hop: owf → prg", () => {
    const route = planRoute("owf", "prg", "forward");
    expect(route).toEqual([{ from: "owf", to: "prg" }]);
  });

  it("direct hop: prg → prf", () => {
    const route = planRoute("prg", "prf", "forward");
    expect(route).toEqual([{ from: "prg", to: "prf" }]);
  });

  it("direct hop: prf → prp", () => {
    const route = planRoute("prf", "prp", "forward");
    expect(route).toEqual([{ from: "prf", to: "prp" }]);
  });

  it("multi-hop: owf → prf (via owf→prg→prf)", () => {
    const route = planRoute("owf", "prf", "forward");
    expect(route).not.toBeNull();
    expect(route.length).toBe(2);
    expect(route[0]).toEqual({ from: "owf", to: "prg" });
    expect(route[1]).toEqual({ from: "prg", to: "prf" });
  });

  it("multi-hop: owf → prp (via owf→prg→prf→prp)", () => {
    const route = planRoute("owf", "prp", "forward");
    expect(route).not.toBeNull();
    expect(route.length).toBeGreaterThanOrEqual(3);
    // First hop must start from owf
    expect(route[0].from).toBe("owf");
    // Last hop must end at prp
    expect(route[route.length - 1].to).toBe("prp");
  });

  it("returns null for unsupported pairs (mac → owf)", () => {
    expect(planRoute("mac", "owf", "forward")).toBeNull();
  });

  it("returns null for self-loop (owf → owf)", () => {
    // planRoute only returns non-trivial paths
    expect(planRoute("owf", "owf", "forward")).toBeNull();
  });
});

describe("planRoute — backward", () => {
  it("backward: prg → owf (reverse of owf→prg)", () => {
    const route = planRoute("prg", "owf", "backward");
    expect(route).toEqual([{ from: "prg", to: "owf" }]);
  });

  it("backward: prf → prg (reverse of prg→prf)", () => {
    const route = planRoute("prf", "prg", "backward");
    expect(route).toEqual([{ from: "prf", to: "prg" }]);
  });

  it("backward: mac → prf (mac has no forward edges; reverse prf→mac)", () => {
    const route = planRoute("mac", "prf", "backward");
    expect(route).not.toBeNull();
    expect(route[0]).toEqual({ from: "mac", to: "prf" });
  });

  it("returns null when no backward path exists", () => {
    // owf has no incoming forward edges, so backward FROM owf to anything is null
    expect(planRoute("owf", "mac", "backward")).toBeNull();
  });
});

// ─── getValidTargets ──────────────────────────────────────────────────────────

describe("getValidTargets", () => {
  it("forward owf → [prg, owp]", () => {
    const targets = getValidTargets("owf", "forward");
    expect(targets).toContain("prg");
    expect(targets).toContain("owp");
  });

  it("forward mac → [] (terminal)", () => {
    expect(getValidTargets("mac", "forward")).toEqual([]);
  });

  it("backward prg → [owf]  (prg was constructed from owf)", () => {
    const targets = getValidTargets("prg", "backward");
    expect(targets).toContain("owf");
  });

  it("backward mac → includes prf and prp", () => {
    const targets = getValidTargets("mac", "backward");
    expect(targets).toContain("prf");
    expect(targets).toContain("prp");
  });

  it("backward owf → [] (nothing constructs owf)", () => {
    // OWF is a bottom primitive — no primitive implies OWF in forward direction
    expect(getValidTargets("owf", "backward")).toEqual([]);
  });
});

// ─── isDirectlySupported ─────────────────────────────────────────────────────

describe("isDirectlySupported", () => {
  it("owf→prg is direct", () => expect(isDirectlySupported("owf", "prg", "forward")).toBe(true));
  it("owf→prf is NOT direct (multi-hop)", () => expect(isDirectlySupported("owf", "prf", "forward")).toBe(false));
  it("backward prg→owf is direct", () => expect(isDirectlySupported("prg", "owf", "backward")).toBe(true));
  it("backward mac→owf is NOT direct", () => expect(isDirectlySupported("mac", "owf", "backward")).toBe(false));
});

// ─── isRouteSupported ────────────────────────────────────────────────────────

describe("isRouteSupported", () => {
  it("owf→prg: true", () => expect(isRouteSupported("owf", "prg")).toBe(true));
  it("owf→prf (multi-hop): true", () => expect(isRouteSupported("owf", "prf")).toBe(true));
  it("owf→mac (multi-hop via prg→prf→mac): true", () => expect(isRouteSupported("owf", "mac")).toBe(true));
  it("mac→owf: false (no path)", () => expect(isRouteSupported("mac", "owf")).toBe(false));
  it("backward prg→owf: true", () => expect(isRouteSupported("prg", "owf", "backward")).toBe(true));
  it("backward owf→mac: false", () => expect(isRouteSupported("owf", "mac", "backward")).toBe(false));
});

// ─── getEffectiveReductionKey ─────────────────────────────────────────────────

describe("getEffectiveReductionKey", () => {
  it("forward owf→prg → 'owf:prg'", () => {
    expect(getEffectiveReductionKey("owf", "prg", "forward")).toBe("owf:prg");
  });

  it("backward prg→owf → 'prg:owf_back'", () => {
    expect(getEffectiveReductionKey("prg", "owf", "backward")).toBe("prg:owf_back");
  });

  it("backward prf→prg → 'prf:prg_back'", () => {
    expect(getEffectiveReductionKey("prf", "prg", "backward")).toBe("prf:prg_back");
  });

  it("forward prg→prf → 'prg:prf'", () => {
    expect(getEffectiveReductionKey("prg", "prf", "forward")).toBe("prg:prf");
  });
});

// ─── describeRoute ─────────────────────────────────────────────────────────────

describe("describeRoute", () => {
  const labels = { owf: "OWF", prg: "PRG", prf: "PRF", prp: "PRP" };

  it("single hop", () => {
    const route = [{ from: "owf", to: "prg" }];
    expect(describeRoute(route, labels)).toBe("OWF → PRG");
  });

  it("two hops", () => {
    const route = [{ from: "owf", to: "prg" }, { from: "prg", to: "prf" }];
    expect(describeRoute(route, labels)).toBe("OWF → PRG → PRF");
  });

  it("three hops", () => {
    const route = [
      { from: "owf", to: "prg" },
      { from: "prg", to: "prf" },
      { from: "prf", to: "prp" },
    ];
    expect(describeRoute(route, labels)).toBe("OWF → PRG → PRF → PRP");
  });

  it("returns empty string for empty/null input", () => {
    expect(describeRoute([], labels)).toBe("");
    expect(describeRoute(null, labels)).toBe("");
  });

  it("falls back to uppercase key when label missing", () => {
    const route = [{ from: "mac", to: "hmac" }];
    expect(describeRoute(route, labels)).toBe("MAC → HMAC");
  });
});
