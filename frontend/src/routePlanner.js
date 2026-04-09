/**
 * routePlanner.js — PA#0: Centralized Clique Graph Routing Engine
 *
 * Implements a real directed-graph BFS router over the Minicrypt clique.
 * All routing decisions live here — never scattered across UI render branches.
 *
 * Public API:
 *   planRoute(source, target, direction)     → [{from, to}, ...] | null
 *   getValidTargets(source, direction)       → string[]
 *   isDirectlySupported(source, target, dir) → boolean
 *   isRouteSupported(source, target, dir)    → boolean
 *   getEffectiveReductionKey(src, tgt, dir)  → string
 */

// ─── Forward directed edges (Minicrypt clique, PA spec) ──────────────────────
// Each key reduces to each value: A → B means "if A exists, B exists".
export const CLIQUE_GRAPH = {
  owf:  ["prg", "owp"],
  owp:  ["prg", "prf"],
  prg:  ["prf"],
  prf:  ["prg", "prp", "mac"],
  prp:  ["mac"],
  mac:  [],
  crhf: ["hmac"],
  hmac: ["mac"],
};

// All known primitives
export const ALL_PRIMITIVES = Object.keys(CLIQUE_GRAPH);

// ─── Build reverse graph (backward direction) ────────────────────────────────
function buildReverseGraph(g) {
  const rev = {};
  for (const node of Object.keys(g)) rev[node] = [];
  for (const [node, neighbors] of Object.entries(g)) {
    for (const n of neighbors) {
      if (!rev[n]) rev[n] = [];
      rev[n].push(node);
    }
  }
  return rev;
}

export const REVERSE_GRAPH = buildReverseGraph(CLIQUE_GRAPH);

// ─── BFS shortest path ────────────────────────────────────────────────────────
/**
 * bfsPath(graph, source, target) → string[] | null
 * Returns the shortest node sequence, or null if no path exists.
 */
function bfsPath(graph, source, target) {
  if (source === target) return [source];
  if (!graph[source]) return null;
  const queue = [[source]];
  const visited = new Set([source]);
  while (queue.length > 0) {
    const path = queue.shift();
    const node = path[path.length - 1];
    for (const neighbor of (graph[node] ?? [])) {
      if (!visited.has(neighbor)) {
        const next = [...path, neighbor];
        if (neighbor === target) return next;
        visited.add(neighbor);
        queue.push(next);
      }
    }
  }
  return null;
}

// ─── Public routing functions ─────────────────────────────────────────────────

/**
 * planRoute(source, target, direction) → [{from, to}, ...] | null
 *
 * Returns the ordered sequence of reduction hops needed to go from source to
 * target.  Returns null when no path exists in the given direction.
 *
 * direction: "forward" | "backward"
 *   forward  — constructive reductions A → B (if A is secure, B is constructible)
 *   backward — breaking reductions B → A (breaking B implies breaking A)
 */
export function planRoute(source, target, direction = "forward") {
  const graph = direction === "forward" ? CLIQUE_GRAPH : REVERSE_GRAPH;
  const path = bfsPath(graph, source, target);
  if (!path || path.length < 2) return null;
  const steps = [];
  for (let i = 0; i < path.length - 1; i++) {
    steps.push({ from: path[i], to: path[i + 1] });
  }
  return steps;
}

/**
 * getValidTargets(source, direction) → string[]
 *
 * Returns the directly adjacent primitives from source in the given direction.
 * These are the options shown in the Target B selector.
 */
export function getValidTargets(source, direction = "forward") {
  const graph = direction === "forward" ? CLIQUE_GRAPH : REVERSE_GRAPH;
  return graph[source] ?? [];
}

/**
 * isDirectlySupported(source, target, direction) → boolean
 * True when source → target is a single edge (no intermediate hop needed).
 */
export function isDirectlySupported(source, target, direction = "forward") {
  return getValidTargets(source, direction).includes(target);
}

/**
 * isRouteSupported(source, target, direction) → boolean
 * True when any path (direct or multi-hop) exists.
 */
export function isRouteSupported(source, target, direction = "forward") {
  return planRoute(source, target, direction) !== null;
}

/**
 * getEffectiveReductionKey(source, target, direction) → string
 *
 * Returns the key to look up in the REDUCTIONS metadata table.
 * For backward reductions, appends "_back" so that:
 *   forward  owf→prg  → "owf:prg"
 *   backward prg→owf  → "prg:owf_back"
 */
export function getEffectiveReductionKey(source, target, direction) {
  if (direction === "backward") return `${source}:${target}_back`;
  return `${source}:${target}`;
}

/**
 * describeRoute(steps) → string
 * Human-readable summary of a multi-hop route, e.g. "OWF → PRG → PRF".
 */
export function describeRoute(steps, labelMap = {}) {
  if (!steps || steps.length === 0) return "";
  const label = k => labelMap[k] ?? k.toUpperCase();
  const nodes = [steps[0].from, ...steps.map(s => s.to)];
  return nodes.map(label).join(" → ");
}
