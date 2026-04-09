const BASE = "http://localhost:8000";

async function post(path, body) {
  const res = await fetch(`${BASE}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!res.ok) {
    const err = await res.json().catch(() => ({ detail: res.statusText }));
    throw new Error(err.detail || "Request failed");
  }
  return res.json();
}

export const api = {
  owf:              (body) => post("/pa1/owf", body),
  owfHardness:      (body) => post("/pa1/owf/verify_hardness", body),
  owfFromPrg:       (body) => post("/pa1/owf_from_prg", body),
  prg:              (body) => post("/pa1/prg", body),
  nist:             (body) => post("/pa1/nist", body),
  prf:              (body) => post("/pa2/prf", body),
  ggmTree:          (body) => post("/pa2/ggm_tree", body),
  prgFromPrf:       (body) => post("/pa2/prg_from_prf", body),
  distinguishGame:  (body) => post("/pa2/distinguishing_game", body),
  // PA3
  pa3Encrypt:       (body) => post("/pa3/encrypt", body),
  pa3Decrypt:       (body) => post("/pa3/decrypt", body),
  pa3CpaGame:       (body) => post("/pa3/cpa_game", body),
  prp:              (body) => post("/pa3/prp", body),
  aesModes:         (body) => post("/pa3/modes", body),
  paddingOracle:    (body) => post("/pa3/padding_oracle", body),
  // PA4
  pa4Modes:         (body) => post("/pa4/modes", body),
  pa4Attacks:       (body) => post("/pa4/attacks", body),
  mac:              (body) => post("/pa4/mac", body),
  lengthExtension:  (body) => post("/pa4/length_extension", body),
  eufCma:           (body) => post("/pa4/euf_cma", body),
  // PA5
  pa5Mac:           (body) => post("/pa5/mac", body),
  pa5EufCma:        (body) => post("/pa5/euf_cma", body),
  // PA6
  pa6Encrypt:       (body) => post("/pa6/encrypt", body),
  pa6Decrypt:       (body) => post("/pa6/decrypt", body),
  pa6CcaGame:       (body) => post("/pa6/cca_game", body),
  pa6Protection:    (body) => post("/pa6/protection_demo", body),
  // PA7
  pa7Hash:          (body) => post("/pa7/hash", body),
  pa7HashBlocks:    (body) => post("/pa7/hash_blocks", body),
  pa7Collision:     (body) => post("/pa7/collision_demo", body),
  // PA8
  pa8Hash:          (body) => post("/pa8/hash", body),
  pa8HashTruncated: (body) => post("/pa8/hash_truncated", body),
  pa8Collision:     (body) => post("/pa8/collision_demo", body),
  // PA9
  pa9Attack:        (body) => post("/pa9/attack", body),
  pa9Compare:       (body) => post("/pa9/compare", body),
  pa9Curve:         (body) => post("/pa9/curve", body),
  pa9LiveDemo:      (body) => post("/pa9/live_demo", body),
  pa9Context:       (body) => post("/pa9/context", body),
  // PA10
  pa10Hmac:         (body) => post("/pa10/hmac", body),
  pa10Encrypt:      (body) => post("/pa10/encrypt", body),
  pa10Decrypt:      (body) => post("/pa10/decrypt", body),
  pa10CcaGame:      (body) => post("/pa10/cca_game", body),
  pa10Protection:   (body) => post("/pa10/protection_demo", body),
  // Part III
  rsaKeygen:        (body) => post("/pa5/rsa_keygen", body),
  rsaEncrypt:       (body) => post("/pa5/rsa_encrypt", body),
  rsaDecrypt:       (body) => post("/pa5/rsa_decrypt", body),
  rsaSign:          (body) => post("/pa5/rsa_sign", body),
  rsaCpaDemo:       (body) => post("/pa5/rsa_cpa_demo", body),
  dhExchange:       (body) => post("/pa5/dh_exchange", body),
  dhMitm:           (body) => post("/pa5/dh_mitm", body),
  authenticatedDh:  (body) => post("/pa5/authenticated_dh", body),
};
