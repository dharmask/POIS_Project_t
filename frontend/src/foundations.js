/**
 * foundations.js — PA#0: Foundation Layer Modules
 *
 * Implements the required AESFoundation and DLPFoundation objects
 * that wrap PA implementations and expose a common Foundation interface.
 *
 * Both share the same interface shape so the rest of the app is agnostic:
 *   foundation.asOWF(input)              → Promise<{output_hex, ...}>
 *   foundation.asPRF(key_hex, x, bits)   → Promise<{output_hex, ...}>  (AES only)
 *   foundation.asPRP(key_hex, pt_hex)    → Promise<{output_hex, ...}>  (AES only)
 *   foundation.asOWP(x)                  → Promise<{output_hex, ...}>  (DLP only)
 *
 * Architectural rule (from PA#0 spec):
 *   Column 2 must ONLY use the source primitive that Column 1 constructed.
 *   Column 2 must NOT call AES or DLP directly. It receives the foundation
 *   object and calls its methods — the foundation is a black box to Column 2.
 */

import { api } from "./api";

// ─── AES Foundation ───────────────────────────────────────────────────────────
// Wraps your PA#2 AES-based PRF. Exposes asOWF(), asPRF(), asPRP().
export const AESFoundation = {
  name: "AES-128 (PRP/PRF)",
  type: "aes",
  description: "AES-128 acts as a concrete PRP (Pseudorandom Permutation) and, by the PRP/PRF switching lemma, also as a PRF. It is the algebraic foundation for the upper half of the Minicrypt clique.",

  /**
   * asOWF(key_hex) → OWF
   * Uses AES as a one-way function: f(k) = AES_k(0¹²⁸) ⊕ k
   * Wraps PA#1/PA#2 AES-based OWF implementation.
   */
  async asOWF(key_hex) {
    return api.owf({ mode: "aes", key_hex });
  },

  /**
   * asPRF(key_hex, x, input_bits) → PRF
   * GGM tree construction using AES as base. Wraps PA#2.
   * This is the primary PRF — the GGM tree built on top of AES.
   */
  async asPRF(key_hex, x, input_bits = 8) {
    return api.prf({ mode: "ggm", key_hex, x: parseInt(x) || 0, input_bits });
  },

  /**
   * asPRP(key_hex, plaintext_hex, mode) → PRP (AES block cipher)
   * AES directly as a PRP. Wraps PA#3 AES implementation.
   */
  async asPRP(key_hex, plaintext_hex, mode = "encrypt") {
    return api.prp({ key_hex, plaintext_hex, mode });
  },

  /**
   * asPRG(seed_hex, output_bits) → PRG
   * PRG built from AES. Wraps PA#1 PRG implementation.
   */
  async asPRG(seed_hex, output_bits = 128) {
    return api.prg({ mode: "aes", seed_hex, output_bits });
  },

  // AES does not provide a natural OWP in the DLP sense
  asOWP: null,
};

// ─── DLP Foundation ───────────────────────────────────────────────────────────
// Wraps your PA#1 DLP-based OWF. Exposes asOWF(), asOWP().
export const DLPFoundation = {
  name: "DLP (gˣ mod p)",
  type: "dlp",
  description: "The Discrete Logarithm Problem (DLP): f(x) = gˣ mod p. This gives a concrete OWF and OWP, and underpins Diffie-Hellman and ElGamal. It is the algebraic foundation for the lower half of the clique.",

  /**
   * asOWF(x) → OWF
   * DLP: f(x) = gˣ mod p. Wraps PA#1 DLP-based OWF.
   */
  async asOWF(x) {
    return api.owf({ mode: "dlp", x: parseInt(x) || 42 });
  },

  /**
   * asOWP(x) → OWP
   * DLP is a bijection on ℤq, hence also a OWP.
   * Same computation as asOWF — the bijectivity is what makes it an OWP.
   */
  async asOWP(x) {
    return api.owf({ mode: "dlp", x: parseInt(x) || 42 });
  },

  /**
   * asPRG(seed_hex, output_bits) → PRG
   * PRG built from DLP via HILL/GL hard-core bit construction. Wraps PA#1.
   */
  async asPRG(seed_hex, output_bits = 128) {
    return api.prg({ mode: "dlp", seed_hex, output_bits });
  },

  // DLP foundation does not directly provide a PRF or PRP
  // (PRF requires OWP→PRG→PRF multi-hop via GGM — available once PAs 1+2 are linked)
  asPRF: null,
  asPRP: null,
};

// ─── Foundation factory ───────────────────────────────────────────────────────
/**
 * getFoundation(type) → AESFoundation | DLPFoundation
 * Returns the foundation object for the given type string.
 * Both objects implement the same interface — the rest of the app is agnostic.
 */
export function getFoundation(type) {
  return type === "aes" ? AESFoundation : DLPFoundation;
}
