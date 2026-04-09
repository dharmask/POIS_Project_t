"""
FastAPI Bridge — CS8.401 POIS Project
=======================================
Exposes PA#1 (OWF + PRG + NIST) and PA#2 (PRF GGM + AES PRF) via REST API.
Run with:  uvicorn backend.api.main:app --reload --port 8000
"""

import os
import sys
import pathlib

# Ensure backend package is importable
_BACKEND = pathlib.Path(__file__).resolve().parent.parent.parent
if str(_BACKEND) not in sys.path:
    sys.path.insert(0, str(_BACKEND))

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from typing import Literal, Optional

from backend.pa1.owf import owf_dlp, owf_aes, DLP_P
from backend.pa1.prg import PRG_DLP, PRG_AES, OWF_from_PRG, make_prg
from backend.pa1.nist_tests import run_all_tests, run_tests_on_bytes, _bits_from_int
from backend.pa2.prf import PRF_GGM, PRF_AES, PRG_from_PRF, distinguishing_game
from backend.pa3.encryption import Dec, Enc, cpa_game
from backend.pa3.prp import (
    PRP_AES, ecb_encrypt, ecb_decrypt, ecb_pattern_demo,
    cbc_encrypt, cbc_decrypt, ctr_crypt,
    padding_oracle_attack, switching_lemma,
)
from backend.pa4.modes import (
    cbc_decrypt as pa4_cbc_decrypt,
    cbc_encrypt as pa4_cbc_encrypt,
    cbc_iv_reuse_demo,
    cpa_malleability_demo,
    ctr_crypt as pa4_ctr_crypt,
    ofb_keystream_reuse_demo,
    ofb_crypt,
)
from backend.pa4.mac import (
    mac_prf, vrfy_prf, cbc_mac, vrfy_cbc_mac,
    hmac_aes, vrfy_hmac_aes, length_extension_demo, euf_cma_game,
)
from backend.pa5.mac import (
    cbc_mac as pa5_cbc_mac,
    euf_cma_game as pa5_euf_cma_game,
    mac_prf as pa5_mac_prf,
    vrfy_cbc_mac as pa5_vrfy_cbc_mac,
    vrfy_prf as pa5_vrfy_prf,
)
from backend.pa5.pubkey import (
    rsa_keygen, rsa_encrypt, rsa_decrypt, rsa_sign, rsa_verify,
    rsa_cpa_demo,
    dh_keygen, dh_shared_secret, dh_exchange_demo,
    dh_mitm_demo, authenticated_dh_demo,
)
from backend.pa6.cca import CCAError, cca2_game, decrypt_then_verify_failure_demo, etm_decrypt, etm_encrypt
from backend.pa7.merkle_damgard import MerkleDamgard, toy_collision_propagation_demo, toy_compress
from backend.pa8.dlp_hash import DLPHash, FULL_PARAMS, TOY_PARAMS, birthday_collision_demo
from backend.pa9.birthday_attack import (
    build_live_demo,
    compare_algorithms_on_toy_hash,
    empirical_birthday_curve,
    modern_hash_context,
    run_collision_attack,
)
from backend.pa10.hmac_cca import (
    HMACCCAError,
    HMACDLP,
    cca2_hmac_game,
    decrypt_then_hmac_demo,
    etm_hmac_decrypt,
    etm_hmac_encrypt,
)

app = FastAPI(
    title="CS8.401 POIS — Minicrypt API",
    description=(
        "PA#1: OWF (DLP + AES) + PRG (HILL/GL) + NIST SP 800-22 tests\n"
        "PA#2: PRF (GGM Tree + AES) + distinguishing game\n"
        "PA#3: PRP (AES Modes: ECB/CBC/CTR) + Padding Oracle\n"
        "PA#4/PA#5 legacy MAC demos: PRF-MAC, CBC-MAC, and length-extension groundwork\n"
        "PA#5: Public-Key (RSA + Diffie-Hellman)\n"
        "PA#7: Merkle-Damgard\n"
        "PA#8: DLP-based Collision-Resistant Hash\n"
        "PA#9: Birthday Attack (Collision Finding)\n"
        "PA#10: HMAC + HMAC-based CCA Encryption"
    ),
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ===========================================================================
# PA#1 Endpoints
# ===========================================================================

class OWFRequest(BaseModel):
    mode: Literal["dlp", "aes"] = "dlp"
    # For DLP mode: integer x
    x: Optional[int] = Field(default=None, description="Input integer (DLP mode)")
    # For AES mode: hex string of 16 bytes
    key_hex: Optional[str] = Field(
        default=None,
        description="16-byte key as hex string (AES mode)"
    )


@app.post("/pa1/owf", tags=["PA1 - OWF"])
def compute_owf(req: OWFRequest):
    """Compute OWF(x) using DLP-based or AES-based construction."""
    try:
        if req.mode == "dlp":
            x = req.x if req.x is not None else int.from_bytes(os.urandom(4), 'big')
            result = owf_dlp(x)
            return {
                "mode": "dlp",
                "input": x,
                "output_hex": hex(result),
                "output_bits": result.bit_length(),
                "description": f"g^x mod p  where g=2, p={DLP_P.bit_length()}-bit safe prime"
            }
        else:
            if req.key_hex:
                k = bytes.fromhex(req.key_hex)
            else:
                k = os.urandom(16)
            result = owf_aes(k)
            return {
                "mode": "aes",
                "input_hex": k.hex(),
                "output_hex": result.hex(),
                "description": "AES_k(0^128) XOR k"
            }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PRGRequest(BaseModel):
    mode: Literal["dlp", "aes"] = "aes"
    seed_hex: Optional[str] = Field(default=None, description="Seed as hex (AES: 16 bytes, DLP: any)")
    seed_int: Optional[int] = Field(default=None, description="Seed as integer (DLP mode)")
    output_bits: int = Field(default=256, ge=8, le=65536)


@app.post("/pa1/prg", tags=["PA1 - PRG"])
def run_prg(req: PRGRequest):
    """Generate pseudorandom bits using HILL/GL PRG from OWF."""
    try:
        prg = make_prg(req.mode, output_bits=req.output_bits)
        if req.mode == "aes":
            seed = bytes.fromhex(req.seed_hex) if req.seed_hex else os.urandom(16)
            prg.seed(seed)
            seed_display = seed.hex()
        else:
            if req.seed_int is not None:
                seed = req.seed_int
            elif req.seed_hex:
                seed = int(req.seed_hex, 16)
            else:
                seed = int.from_bytes(os.urandom(4), 'big')
            prg.seed(seed)
            seed_display = hex(seed)

        bits_int = prg.next_bits(req.output_bits)
        bits_hex = hex(bits_int)
        bits_list = [(bits_int >> (req.output_bits - 1 - i)) & 1
                     for i in range(req.output_bits)]
        ones = sum(bits_list)
        zeros = req.output_bits - ones

        return {
            "mode": req.mode,
            "seed": seed_display,
            "output_bits": req.output_bits,
            "output_hex": bits_hex,
            "statistics": {
                "ones": ones,
                "zeros": zeros,
                "ones_ratio": round(ones / req.output_bits, 4),
            }
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class NISTRequest(BaseModel):
    mode: Literal["dlp", "aes"] = "aes"
    seed_hex: Optional[str] = None
    seed_int: Optional[int] = None
    n_bits: int = Field(default=20000, ge=100, le=1000000)


@app.post("/pa1/nist", tags=["PA1 - NIST Tests"])
def run_nist(req: NISTRequest):
    """Run NIST SP 800-22 statistical tests (frequency, runs, serial) on PRG output."""
    try:
        prg = make_prg(req.mode, output_bits=req.n_bits)
        if req.mode == "aes":
            seed = bytes.fromhex(req.seed_hex) if req.seed_hex else os.urandom(16)
            prg.seed(seed)
            seed_display = seed.hex()
        else:
            if req.seed_int is not None:
                seed = req.seed_int
            elif req.seed_hex:
                seed = int(req.seed_hex, 16)
            else:
                seed = int.from_bytes(os.urandom(4), 'big')
            prg.seed(seed)
            seed_display = hex(seed)

        results = run_all_tests(prg, seed, req.n_bits)
        all_pass = all(r['pass'] for r in results if r['p_value'] is not None)

        return {
            "mode": req.mode,
            "seed": seed_display,
            "n_bits": req.n_bits,
            "overall_pass": all_pass,
            "tests": results
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class OWFHardnessRequest(BaseModel):
    mode: Literal["dlp", "aes"] = "dlp"
    n_trials: int = Field(default=50, ge=10, le=200)


@app.post("/pa1/owf/verify_hardness", tags=["PA1 - OWF"])
def verify_owf_hardness(req: OWFHardnessRequest):
    """
    Demonstrate OWF hardness: random inversion succeeds with negligible probability.
    For each trial: pick random x, compute y=f(x), attempt random inversion, check if f(guess)==y.
    """
    try:
        successes = 0
        trials_detail = []

        for _ in range(req.n_trials):
            if req.mode == "dlp":
                # Random x in [1, 2^30] for fast demo (toy parameters)
                x = int.from_bytes(os.urandom(4), 'big') % (2**30) + 1
                y = owf_dlp(x)
                # Adversary guesses a random x in the same range
                guess = int.from_bytes(os.urandom(4), 'big') % (2**30) + 1
                y_guess = owf_dlp(guess)
                hit = (y_guess == y)
                if hit:
                    successes += 1
                trials_detail.append({
                    "x": x, "y_hex": hex(y),
                    "guess": guess, "y_guess_hex": hex(y_guess), "hit": hit
                })
            else:
                k = os.urandom(16)
                y = owf_aes(k)
                guess = os.urandom(16)
                y_guess = owf_aes(guess)
                hit = (y_guess == y)
                if hit:
                    successes += 1
                trials_detail.append({
                    "x": k.hex(), "y_hex": y.hex(),
                    "guess": guess.hex(), "y_guess_hex": y_guess.hex(), "hit": hit
                })

        success_rate = successes / req.n_trials
        return {
            "mode": req.mode,
            "n_trials": req.n_trials,
            "successes": successes,
            "success_rate": success_rate,
            "conclusion": (
                "OWF hardness verified — random inversion success rate ≈ 0"
                if success_rate < 0.01
                else "WARNING: unexpectedly high success rate"
            ),
            "trials": trials_detail[:10],  # show first 10 for display
            "description": (
                "f(x) = g^x mod p; adversary picks random guess x' and checks f(x') == f(x)"
                if req.mode == "dlp"
                else "f(k) = AES_k(0^128) ⊕ k; adversary picks random key guess k'"
            ),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class OWFFromPRGRequest(BaseModel):
    mode: Literal["dlp", "aes"] = "aes"
    seed_hex: Optional[str] = None
    output_bits: int = Field(default=256, ge=64, le=2048)


@app.post("/pa1/owf_from_prg", tags=["PA1 - OWF"])
def owf_from_prg_endpoint(req: OWFFromPRGRequest):
    """
    Backward reduction: PRG => OWF.
    Demonstrates that f(s) = G(s) is a one-way function.
    If an adversary could invert f, they could recover the PRG seed directly.
    """
    try:
        prg = make_prg(req.mode, output_bits=req.output_bits)
        owf_fn = OWF_from_PRG(prg)

        if req.mode == "aes":
            seed = bytes.fromhex(req.seed_hex) if req.seed_hex else os.urandom(16)
            seed_display = seed.hex()
            seed_val = seed
        else:
            seed_val = int(req.seed_hex, 16) if req.seed_hex else int.from_bytes(os.urandom(4), 'big') % (2**30) + 1
            seed_display = hex(seed_val)

        # Compute the OWF output directly from the PRG.
        prg.seed(seed_val)
        full_int = prg.next_bits(req.output_bits)
        owf_fn = OWF_from_PRG(prg)

        # Attempt random inversion: pick 20 random seeds, check if any produce the same output.
        inversion_attempts = 20
        inversions_found = 0
        for _ in range(inversion_attempts):
            if req.mode == "aes":
                rand_seed = os.urandom(16)
            else:
                rand_seed = int.from_bytes(os.urandom(4), 'big') % (2**30) + 1
            candidate = owf_fn.compute(rand_seed)
            if candidate == full_int:
                inversions_found += 1

        return {
            "mode": req.mode,
            "seed": seed_display,
            "output_bits": req.output_bits,
            "full_prg_output_hex": hex(full_int),
            "owf_output_hex": hex(full_int),
            "inversion_attempts": inversion_attempts,
            "inversions_found": inversions_found,
            "hardness_verified": inversions_found == 0,
            "description": (
                "f(s) = G(s). "
                "Reduction: if an adversary inverts f, they recover the seed s "
                "from the PRG output itself."
            ),
            "theorem": "PRG => OWF: Any PRG G is itself a OWF. Define f(s) = G(s).",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================================================
# PA#2 Endpoints
# ===========================================================================

class PRFRequest(BaseModel):
    mode: Literal["ggm", "aes"] = "ggm"
    key_hex: Optional[str] = Field(default=None, description="16-byte key as hex")
    x: Optional[int] = Field(default=None, description="PRF input (integer)")
    input_bits: int = Field(default=8, ge=1, le=64)


@app.post("/pa2/prf", tags=["PA2 - PRF"])
def compute_prf(req: PRFRequest):
    """Evaluate PRF F_k(x) using GGM tree or AES construction."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        x = req.x if req.x is not None else int.from_bytes(os.urandom(2), 'big') % (2 ** req.input_bits)

        if req.mode == "ggm":
            prf = PRF_GGM(input_bits=req.input_bits)
            output = prf.evaluate(key, x)
            desc = "GGM tree: F_k(x) = G_{x_n}(...G_{x_1}(k)...)"
        else:
            prf = PRF_AES()
            output = prf.evaluate(key, x)
            desc = "AES PRF: F_k(x) = AES_k(x)"

        return {
            "mode": req.mode,
            "key_hex": key.hex(),
            "input": x,
            "input_bits": req.input_bits,
            "output_hex": output.hex(),
            "output_int": int.from_bytes(output, 'big'),
            "description": desc
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class GGMTreeRequest(BaseModel):
    key_hex: Optional[str] = Field(default=None, description="16-byte key as hex")
    x: Optional[int] = Field(default=None, description="Query integer")
    input_bits: int = Field(default=4, ge=1, le=8)


@app.post("/pa2/ggm_tree", tags=["PA2 - GGM Tree"])
def ggm_tree_endpoint(req: GGMTreeRequest):
    """
    Return GGM tree path + sibling nodes for visualisation.
    For each level, returns the on-path node and its sibling so the frontend
    can draw the tree with the active path highlighted in blue.
    """
    try:
        from backend.pa2.prf import _doubling_prg, _bits_msb_first, _coerce_key, _coerce_domain_value

        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        key = _coerce_key(key)
        n = req.input_bits
        x_int = _coerce_domain_value(req.x if req.x is not None else 0, n)
        bits = _bits_msb_first(x_int, n)
        x_binary = bin(x_int)[2:].zfill(n)

        levels = []
        current = key

        # Level 0: root
        levels.append({
            "level": 0,
            "is_root": True,
            "full_hex": current.hex(),
            "label": "k",
        })

        # Levels 1..n: path node + sibling at each step
        for i, bit in enumerate(bits):
            left, right = _doubling_prg(current)
            path_child  = right if bit else left
            sibling     = left  if bit else right
            is_leaf     = (i == n - 1)
            levels.append({
                "level": i + 1,
                "path_bit": bit,
                "path_full_hex": path_child.hex(),
                "sibling_full_hex": sibling.hex(),
                "is_leaf": is_leaf,
            })
            current = path_child

        return {
            "key_hex": key.hex(),
            "input": x_int,
            "input_bits": n,
            "path_bits": bits,
            "x_binary": x_binary,
            "levels": levels,
            "output_hex": current.hex(),
            "leaf_label": f"F_k({x_binary}) = F_k({x_int})",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PRGFromPRFRequest(BaseModel):
    key_hex: Optional[str] = None
    seed_int: Optional[int] = None
    n_bytes: int = Field(default=64, ge=1, le=4096)
    input_bits: int = Field(default=8, ge=2, le=64)


@app.post("/pa2/prg_from_prf", tags=["PA2 - PRF to PRG"])
def prg_from_prf_endpoint(req: PRGFromPRFRequest):
    """Demonstrate PRG built from PRF: G_k(s) = F_k(s||0) || F_k(s||1)."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        seed = req.seed_int if req.seed_int is not None else 0

        prg = PRG_from_PRF(input_bits=req.input_bits)
        prg.seed(key, seed)
        output = prg.generate_bytes(req.n_bytes)

        from backend.pa1.nist_tests import run_tests_on_bytes
        nist = run_tests_on_bytes(output) if len(output) * 8 >= 100 else []

        return {
            "key_hex": key.hex(),
            "seed": seed,
            "n_bytes": req.n_bytes,
            "output_hex": output.hex(),
            "description": "PRG from PRF: G_k(s) = F_k(s||0) || F_k(s||1)",
            "nist_tests": nist
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class DistGameRequest(BaseModel):
    n_queries: int = Field(default=20, ge=1, le=1000)
    input_bits: int = Field(default=8, ge=1, le=32)


@app.post("/pa2/distinguishing_game", tags=["PA2 - Security Demo"])
def run_distinguishing_game(req: DistGameRequest):
    """Run PRF distinguishing game — demonstrates PRF security."""
    try:
        result = distinguishing_game(
            n_queries=req.n_queries,
            input_bits=req.input_bits
        )
        return result
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================================================
# PA#3 Endpoints
# ===========================================================================

class PA3EncryptRequest(BaseModel):
    scheme: Literal["secure", "broken"] = "secure"
    prf_mode: Literal["aes", "ggm"] = "aes"
    key_hex: Optional[str] = None
    message: Optional[str] = None
    message_hex: Optional[str] = None


@app.post("/pa3/encrypt", tags=["PA3 - CPA Encryption"])
def pa3_encrypt(req: PA3EncryptRequest):
    """Encrypt with the PRF-based CPA-secure construction."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        if req.message_hex is not None:
            message = bytes.fromhex(req.message_hex)
        else:
            message = (req.message or "PA3 challenge message").encode()
        ciphertext = Enc(key, message, scheme=req.scheme, prf_mode=req.prf_mode)
        return {
            "scheme": req.scheme,
            "prf_mode": req.prf_mode,
            "key_hex": key.hex(),
            "message_hex": message.hex(),
            "message_text": message.decode("utf-8", errors="replace"),
            "ciphertext_hex": ciphertext.hex(),
            "nonce_hex": ciphertext[:8].hex(),
            "description": (
                "Enc(k, m) = r || (m xor stream_F(k, r))"
                if req.scheme == "secure"
                else "Broken deterministic variant reuses a fixed nonce and is not CPA-secure"
            ),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PA3DecryptRequest(BaseModel):
    scheme: Literal["secure", "broken"] = "secure"
    prf_mode: Literal["aes", "ggm"] = "aes"
    key_hex: str
    ciphertext_hex: str


@app.post("/pa3/decrypt", tags=["PA3 - CPA Encryption"])
def pa3_decrypt(req: PA3DecryptRequest):
    """Decrypt a PRF-based ciphertext."""
    try:
        key = bytes.fromhex(req.key_hex)
        ciphertext = bytes.fromhex(req.ciphertext_hex)
        message = Dec(key, ciphertext, scheme=req.scheme, prf_mode=req.prf_mode)
        return {
            "scheme": req.scheme,
            "prf_mode": req.prf_mode,
            "key_hex": key.hex(),
            "ciphertext_hex": ciphertext.hex(),
            "message_hex": message.hex(),
            "message_text": message.decode("utf-8", errors="replace"),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PA3CPAGameRequest(BaseModel):
    scheme: Literal["secure", "broken"] = "secure"
    prf_mode: Literal["aes", "ggm"] = "aes"
    trials: int = Field(default=200, ge=10, le=5000)


@app.post("/pa3/cpa_game", tags=["PA3 - CPA Encryption"])
def pa3_cpa_game(req: PA3CPAGameRequest):
    """Run the IND-CPA game against the secure or broken scheme."""
    try:
        return cpa_game(scheme=req.scheme, prf_mode=req.prf_mode, trials=req.trials)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

class PRPRequest(BaseModel):
    key_hex: Optional[str] = None
    plaintext_hex: Optional[str] = None
    direction: Literal["forward", "inverse"] = "forward"


@app.post("/pa3/prp", tags=["PA3 - PRP"])
def compute_prp(req: PRPRequest):
    """Evaluate AES-128 as a PRP (forward or inverse) and verify bijectivity."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        pt  = bytes.fromhex(req.plaintext_hex) if req.plaintext_hex else os.urandom(16)
        if len(pt) != 16: pt = pt[:16].ljust(16, b'\x00')
        prp = PRP_AES(key)
        if req.direction == "forward":
            out = prp.forward(pt)
            inv = prp.inverse(out)
            bijection_ok = inv == pt
        else:
            out = prp.inverse(pt)
            fwd = prp.forward(out)
            bijection_ok = fwd == pt
        return {
            "direction": req.direction,
            "key_hex": key.hex(),
            "input_hex": pt.hex(),
            "output_hex": out.hex(),
            "bijection_verified": bijection_ok,
            "switching_lemma": switching_lemma(10),
            "description": "F_k(x) = AES_k(x)" if req.direction == "forward" else "F_k^{-1}(y) = AES_k^{-1}(y)",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class ModeRequest(BaseModel):
    mode: Literal["ecb", "cbc", "ctr"] = "cbc"
    key_hex: Optional[str] = None
    plaintext: Optional[str] = None
    plaintext_hex: Optional[str] = None
    iv_hex: Optional[str] = None
    nonce_hex: Optional[str] = None
    show_pattern_demo: bool = False


@app.post("/pa3/modes", tags=["PA3 - AES Modes"])
def aes_modes(req: ModeRequest):
    """Encrypt with ECB / CBC / CTR mode. Shows pattern leakage for ECB."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        if req.plaintext_hex:
            pt = bytes.fromhex(req.plaintext_hex)
        elif req.plaintext:
            pt = req.plaintext.encode()
        else:
            pt = b"Hello, AES World! This is block 2"

        if req.mode == "ecb":
            ct = ecb_encrypt(pt, key)
            recovered = ecb_decrypt(ct, key)
            pattern_demo = ecb_pattern_demo(key)
            return {
                "mode": "ecb",
                "key_hex": key.hex(),
                "plaintext": pt.decode("utf-8", errors="replace"),
                "plaintext_hex": pt.hex(),
                "ciphertext_hex": ct.hex(),
                "ciphertext_blocks": [ct[i:i+16].hex() for i in range(0, len(ct), 16)],
                "decrypted": recovered.decode("utf-8", errors="replace"),
                "pattern_demo": pattern_demo,
                "security": "INSECURE — ECB is not CPA-secure (identical blocks leak)",
            }
        elif req.mode == "cbc":
            iv = bytes.fromhex(req.iv_hex) if req.iv_hex else None
            iv_used, ct = cbc_encrypt(pt, key, iv)
            recovered = cbc_decrypt(ct, key, iv_used)
            return {
                "mode": "cbc",
                "key_hex": key.hex(),
                "iv_hex": iv_used.hex(),
                "plaintext": pt.decode("utf-8", errors="replace"),
                "plaintext_hex": pt.hex(),
                "ciphertext_hex": ct.hex(),
                "ciphertext_blocks": [ct[i:i+16].hex() for i in range(0, len(ct), 16)],
                "decrypted": recovered.decode("utf-8", errors="replace"),
                "security": "CPA-secure with random IV",
            }
        else:  # ctr
            nonce = bytes.fromhex(req.nonce_hex) if req.nonce_hex else None
            nonce_used, ct = ctr_crypt(pt, key, nonce)
            _, recovered = ctr_crypt(ct, key, nonce_used)
            return {
                "mode": "ctr",
                "key_hex": key.hex(),
                "nonce_hex": nonce_used.hex(),
                "plaintext": pt.decode("utf-8", errors="replace"),
                "plaintext_hex": pt.hex(),
                "ciphertext_hex": ct.hex(),
                "decrypted": recovered.decode("utf-8", errors="replace"),
                "security": "CPA-secure, parallelizable, no padding needed",
            }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PaddingOracleRequest(BaseModel):
    key_hex: Optional[str] = None
    plaintext: Optional[str] = "Secret message!!"


@app.post("/pa3/padding_oracle", tags=["PA3 - Padding Oracle"])
def run_padding_oracle(req: PaddingOracleRequest):
    """Simulate a padding oracle attack on CBC. Recovers plaintext byte-by-byte."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        pt  = (req.plaintext or "Secret message!!").encode()
        # Pad to exactly 16 bytes for single-block demo
        pt = pt[:16].ljust(16, b'\x00')
        # Encrypt with CBC
        iv, ct = cbc_encrypt(pt, key)
        # Attack: recover the first (and only) ciphertext block
        result = padding_oracle_attack(ct[:16], iv, key)
        return {
            "key_hex": key.hex(),
            "original_plaintext": pt.decode("utf-8", errors="replace"),
            "iv_hex": iv.hex(),
            "ciphertext_hex": ct.hex(),
            "attack": result,
            "security_note": "CBC is CPA-secure but NOT CCA-secure — padding oracle breaks it!",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================================================
# PA#4 Endpoints
# ===========================================================================

class PA4ModeRequest(BaseModel):
    mode: Literal["cbc", "ofb", "ctr"] = "cbc"
    key_hex: Optional[str] = None
    plaintext: Optional[str] = None
    plaintext_hex: Optional[str] = None
    iv_hex: Optional[str] = None
    nonce_hex: Optional[str] = None


@app.post("/pa4/modes", tags=["PA4 - Modes"])
def pa4_modes(req: PA4ModeRequest):
    """Encrypt/decrypt using CBC, OFB, or CTR mode."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        if req.plaintext_hex:
            pt = bytes.fromhex(req.plaintext_hex)
        else:
            pt = (req.plaintext or "PA4 mode demo").encode()

        if req.mode == "cbc":
            iv = bytes.fromhex(req.iv_hex) if req.iv_hex else None
            iv_used, ct = pa4_cbc_encrypt(pt, key, iv)
            recovered = pa4_cbc_decrypt(ct, key, iv_used)
            return {
                "mode": "cbc",
                "key_hex": key.hex(),
                "iv_hex": iv_used.hex(),
                "plaintext_hex": pt.hex(),
                "ciphertext_hex": ct.hex(),
                "decrypted_hex": recovered.hex(),
                "decrypted_text": recovered.decode("utf-8", errors="replace"),
            }
        if req.mode == "ofb":
            iv = bytes.fromhex(req.iv_hex) if req.iv_hex else None
            iv_used, ct = ofb_crypt(pt, key, iv)
            _, recovered = ofb_crypt(ct, key, iv_used)
            return {
                "mode": "ofb",
                "key_hex": key.hex(),
                "iv_hex": iv_used.hex(),
                "plaintext_hex": pt.hex(),
                "ciphertext_hex": ct.hex(),
                "decrypted_hex": recovered.hex(),
                "decrypted_text": recovered.decode("utf-8", errors="replace"),
            }
        nonce = bytes.fromhex(req.nonce_hex) if req.nonce_hex else None
        nonce_used, ct = pa4_ctr_crypt(pt, key, nonce)
        _, recovered = pa4_ctr_crypt(ct, key, nonce_used)
        return {
            "mode": "ctr",
            "key_hex": key.hex(),
            "nonce_hex": nonce_used.hex(),
            "plaintext_hex": pt.hex(),
            "ciphertext_hex": ct.hex(),
            "decrypted_hex": recovered.hex(),
            "decrypted_text": recovered.decode("utf-8", errors="replace"),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PA4AttackRequest(BaseModel):
    attack: Literal["cbc_iv_reuse", "ofb_keystream_reuse", "cpa_malleability"] = "cbc_iv_reuse"
    key_hex: Optional[str] = None


@app.post("/pa4/attacks", tags=["PA4 - Modes"])
def pa4_attacks(req: PA4AttackRequest):
    """Run mode-specific attack demos."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else None
        if req.attack == "cbc_iv_reuse":
            return cbc_iv_reuse_demo(key)
        if req.attack == "ofb_keystream_reuse":
            return ofb_keystream_reuse_demo(key)
        return cpa_malleability_demo(key)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))

class MACRequest(BaseModel):
    mac_mode: Literal["prf", "cbc", "hmac"] = "hmac"
    key_hex: Optional[str] = None
    message: Optional[str] = "Authenticate this message"
    tag_hex: Optional[str] = None


@app.post("/pa4/mac", tags=["PA4 - MAC"])
def compute_mac(req: MACRequest):
    """Compute a MAC tag using PRF-MAC, CBC-MAC, or HMAC-AES."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        msg = (req.message or "").encode()

        if req.mac_mode == "prf":
            m16 = msg[:16].ljust(16, b'\x00')
            tag = mac_prf(key, m16)
            desc = "Mac_k(m) = AES_k(m) — secure PRF-MAC for 16-byte messages"
        elif req.mac_mode == "cbc":
            tag = cbc_mac(key, msg)
            desc = "CBC-MAC: T_i = AES_k(m_i ⊕ T_{i-1})"
        else:
            tag = hmac_aes(key, msg)
            desc = "HMAC_k(m) = H((k⊕opad) ‖ H((k⊕ipad) ‖ m))"

        verify = None
        if req.tag_hex:
            provided = bytes.fromhex(req.tag_hex)
            verify = tag == provided

        return {
            "mac_mode": req.mac_mode,
            "key_hex": key.hex(),
            "message": req.message,
            "tag_hex": tag.hex(),
            "tag_bits": len(tag) * 8,
            "description": desc,
            "verified": verify,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class LengthExtRequest(BaseModel):
    key_hex: Optional[str] = None
    message: Optional[str] = "user=alice&role=user"


@app.post("/pa4/length_extension", tags=["PA4 - Length Extension"])
def length_extension(req: LengthExtRequest):
    """Demonstrate length-extension attack on naive H(k‖m) vs HMAC immunity."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        msg = (req.message or "user=alice&role=user").encode()
        return length_extension_demo(key, msg)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class EUFCMARequest(BaseModel):
    mac_mode: Literal["prf", "cbc", "hmac"] = "hmac"
    n_queries: int = Field(default=10, ge=1, le=50)


@app.post("/pa4/euf_cma", tags=["PA4 - EUF-CMA Game"])
def run_euf_cma(req: EUFCMARequest):
    """Run the MAC EUF-CMA security game. Adversary tries to forge a tag."""
    try:
        return euf_cma_game(mac_mode=req.mac_mode, n_queries=req.n_queries)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================================================
# PA#5 Endpoints
# ===========================================================================

class PA5MACRequest(BaseModel):
    mac_mode: Literal["prf", "cbc"] = "prf"
    key_hex: Optional[str] = None
    message: Optional[str] = "Authenticate this message"
    message_hex: Optional[str] = None
    tag_hex: Optional[str] = None


@app.post("/pa5/mac", tags=["PA5 - MAC"])
def pa5_mac(req: PA5MACRequest):
    """Compute or verify a PA#5 MAC."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        message = bytes.fromhex(req.message_hex) if req.message_hex else (req.message or "").encode()
        if req.mac_mode == "prf":
            tag = pa5_mac_prf(key, message)
            verified = None if req.tag_hex is None else pa5_vrfy_prf(key, message, bytes.fromhex(req.tag_hex))
            description = "PRF-MAC: Mac_k(m) = F_k(pad(m))"
        else:
            tag = pa5_cbc_mac(key, message)
            verified = None if req.tag_hex is None else pa5_vrfy_cbc_mac(key, message, bytes.fromhex(req.tag_hex))
            description = "CBC-MAC with a length prefix for variable-length messages"
        return {
            "mac_mode": req.mac_mode,
            "key_hex": key.hex(),
            "message_hex": message.hex(),
            "message_text": message.decode("utf-8", errors="replace"),
            "tag_hex": tag.hex(),
            "verified": verified,
            "description": description,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PA5EUFCMARequest(BaseModel):
    mac_mode: Literal["prf", "cbc"] = "prf"
    n_queries: int = Field(default=10, ge=1, le=100)


@app.post("/pa5/euf_cma", tags=["PA5 - MAC"])
def pa5_euf_cma(req: PA5EUFCMARequest):
    """Run the PA#5 EUF-CMA game."""
    try:
        return pa5_euf_cma_game(mac_mode=req.mac_mode, n_queries=req.n_queries)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PA6EncryptRequest(BaseModel):
    key_hex: Optional[str] = None
    message: Optional[str] = None
    message_hex: Optional[str] = None


@app.post("/pa6/encrypt", tags=["PA6 - CCA Encryption"])
def pa6_encrypt(req: PA6EncryptRequest):
    """Encrypt with Encrypt-then-MAC."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        message = bytes.fromhex(req.message_hex) if req.message_hex else (req.message or "PA6 protected message").encode()
        bundle = etm_encrypt(key, message)
        return {
            "key_hex": key.hex(),
            "message_hex": message.hex(),
            "message_text": message.decode("utf-8", errors="replace"),
            "ciphertext_hex": bundle.hex(),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PA6DecryptRequest(BaseModel):
    key_hex: str
    ciphertext_hex: str


@app.post("/pa6/decrypt", tags=["PA6 - CCA Encryption"])
def pa6_decrypt(req: PA6DecryptRequest):
    """Decrypt an Encrypt-then-MAC ciphertext."""
    try:
        key = bytes.fromhex(req.key_hex)
        bundle = bytes.fromhex(req.ciphertext_hex)
        message = etm_decrypt(key, bundle)
        return {
            "key_hex": key.hex(),
            "ciphertext_hex": bundle.hex(),
            "message_hex": message.hex(),
            "message_text": message.decode("utf-8", errors="replace"),
        }
    except CCAError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PA6CCAGameRequest(BaseModel):
    trials: int = Field(default=100, ge=10, le=2000)


@app.post("/pa6/cca_game", tags=["PA6 - CCA Encryption"])
def pa6_cca_game(req: PA6CCAGameRequest):
    """Run the PA#6 CCA2 game."""
    try:
        return cca2_game(req.trials)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa6/protection_demo", tags=["PA6 - CCA Encryption"])
def pa6_protection_demo():
    """Compare bare CPA encryption with Encrypt-then-MAC under tampering."""
    try:
        return decrypt_then_verify_failure_demo()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================================================
# PA#7 Endpoints
# ===========================================================================

class PA7HashRequest(BaseModel):
    message: Optional[str] = "hello merkle-damgard"
    message_hex: Optional[str] = None
    iv_hex: Optional[str] = None
    block_size: int = Field(default=8, ge=2, le=64)
    output_size: int = Field(default=4, ge=1, le=32)

class PA7BlocksRequest(BaseModel):
    blocks_hex: list[str]
    iv_hex: Optional[str] = None
    block_size: int = Field(default=8, ge=2, le=64)
    output_size: int = Field(default=4, ge=1, le=32)


@app.post("/pa7/hash", tags=["PA7 - Merkle-Damgard"])
def pa7_hash(req: PA7HashRequest):
    """Run the PA#7 Merkle-Damgard hash with the toy compression function."""
    try:
        message = bytes.fromhex(req.message_hex) if req.message_hex else (req.message or "").encode()
        iv = bytes.fromhex(req.iv_hex) if req.iv_hex else bytes(req.output_size)
        md = MerkleDamgard(
            compress=toy_compress,
            iv=iv,
            block_size=req.block_size,
            output_size=req.output_size,
        )
        trace = md.trace(message)
        return {
            "compression": "toy_xor",
            "message_text": message.decode("utf-8", errors="replace"),
            **trace,
            "description": (
                "Generic Merkle-Damgard transform using MD-strengthening padding "
                "and the PA#7 toy XOR-based compression function."
            ),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa7/hash_blocks", tags=["PA7 - Merkle-Damgard"])
def pa7_hash_blocks(req: PA7BlocksRequest):
    """Replay the PA#7 chain over an explicit list of already-padded blocks."""
    try:
        iv = bytes.fromhex(req.iv_hex) if req.iv_hex else bytes(req.output_size)
        md = MerkleDamgard(
            compress=toy_compress,
            iv=iv,
            block_size=req.block_size,
            output_size=req.output_size,
        )
        blocks = [bytes.fromhex(block_hex) for block_hex in req.blocks_hex]
        trace = md.trace_blocks(blocks)
        return {
            "compression": "toy_xor",
            **trace,
            "description": (
                "Replay mode for the PA7 viewer. "
                "Computes the chain over explicit block values so the frontend can edit a block "
                "and recompute from that point onward."
            ),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa7/collision_demo", tags=["PA7 - Merkle-Damgard"])
def pa7_collision_demo():
    """Show how a collision in the toy compression function propagates to the full MD hash."""
    try:
        return toy_collision_propagation_demo()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================================================
# PA#8 Endpoints
# ===========================================================================

class PA8HashRequest(BaseModel):
    message: Optional[str] = "hello dlp hash"
    message_hex: Optional[str] = None
    output_bits: Optional[int] = Field(default=None, ge=1, le=768)
    use_toy_params: bool = False


class PA8CollisionRequest(BaseModel):
    bits: int = Field(default=16, ge=1, le=16)
    max_attempts: int = Field(default=50000, ge=32, le=500000)


def _pa8_params(use_toy_params: bool):
    return TOY_PARAMS if use_toy_params else FULL_PARAMS


@app.post("/pa8/hash", tags=["PA8 - DLP Hash"])
def pa8_hash(req: PA8HashRequest):
    """Compute the PA#8 DLP-based CRHF and return the Merkle-Damgard trace."""
    try:
        params = _pa8_params(req.use_toy_params)
        message = bytes.fromhex(req.message_hex) if req.message_hex else (req.message or "").encode()
        trace = DLPHash(params).trace(message, req.output_bits)
        digest_bytes = bytes.fromhex(trace["digest_hex"])
        return {
            "message_text": message.decode("utf-8", errors="replace"),
            "message_hex": message.hex(),
            "digest_bytes_hex": digest_bytes.hex(),
            "digest_length_bytes": len(digest_bytes),
            "use_toy_params": req.use_toy_params,
            "description": (
                "PA#8 DLP-based CRHF using the PA#7 Merkle-Damgard transform "
                "and compression h(x, y) = g^x * h_hat^y mod p."
            ),
            **trace,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa8/hash_truncated", tags=["PA8 - DLP Hash"])
def pa8_hash_truncated(req: PA8HashRequest):
    """Compute a truncated PA#8 digest for birthday experiments."""
    try:
        if req.output_bits is None:
            raise ValueError("output_bits is required for the truncated endpoint")
        params = _pa8_params(req.use_toy_params)
        message = bytes.fromhex(req.message_hex) if req.message_hex else (req.message or "").encode()
        digest = DLPHash(params).hash_truncated(message, req.output_bits)
        return {
            "message_text": message.decode("utf-8", errors="replace"),
            "message_hex": message.hex(),
            "digest_hex": digest.hex(),
            "output_bits": req.output_bits,
            "parameter_set": params.name,
            "use_toy_params": req.use_toy_params,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa8/collision_demo", tags=["PA8 - DLP Hash"])
def pa8_collision_demo(req: PA8CollisionRequest):
    """Run a birthday-style collision search on the truncated toy PA#8 hash."""
    try:
        return birthday_collision_demo(
            bits=req.bits,
            params=TOY_PARAMS,
            max_attempts=req.max_attempts,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================================================
# PA#9 Endpoints
# ===========================================================================

class PA9AttackRequest(BaseModel):
    hash_kind: Literal["toy", "dlp"] = "toy"
    algorithm: Literal["naive", "floyd"] = "naive"
    n_bits: int = Field(default=16, ge=4, le=16)


class PA9CompareRequest(BaseModel):
    trials: int = Field(default=24, ge=2, le=200)


class PA9CurveRequest(BaseModel):
    trials: int = Field(default=100, ge=10, le=200)


class PA9DemoRequest(BaseModel):
    n_bits: int = Field(default=12, ge=8, le=16)


class PA9ContextRequest(BaseModel):
    hash_rate_per_second: int = Field(default=10**9, ge=1, le=10**15)


@app.post("/pa9/attack", tags=["PA9 - Birthday Attack"])
def pa9_attack(req: PA9AttackRequest):
    """Run the naive or Floyd birthday attack on the toy hash or truncated PA#8 hash."""
    try:
        return run_collision_attack(
            hash_kind=req.hash_kind,
            algorithm=req.algorithm,
            n_bits=req.n_bits,
        )
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa9/compare", tags=["PA9 - Birthday Attack"])
def pa9_compare(req: PA9CompareRequest):
    """Compare naive birthday search against Floyd's cycle-finding on the toy hash."""
    try:
        return compare_algorithms_on_toy_hash(trials=req.trials)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa9/curve", tags=["PA9 - Birthday Attack"])
def pa9_curve(req: PA9CurveRequest):
    """Run the 100-trial empirical birthday-curve experiment on the toy hash."""
    try:
        return empirical_birthday_curve(trials=req.trials)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa9/live_demo", tags=["PA9 - Birthday Attack"])
def pa9_live_demo(req: PA9DemoRequest):
    """Prepare one collision search instance plus theory points for the PA#9 live demo."""
    try:
        return build_live_demo(req.n_bits)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa9/context", tags=["PA9 - Birthday Attack"])
def pa9_context(req: PA9ContextRequest):
    """Estimate the birthday-attack cost for MD5 and SHA-1 at a given hash rate."""
    try:
        return modern_hash_context(req.hash_rate_per_second)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================================================
# PA#10 Endpoints
# ===========================================================================

class PA10HMACRequest(BaseModel):
    key_hex: Optional[str] = None
    message: Optional[str] = "authenticate with pa10"
    message_hex: Optional[str] = None
    tag_hex: Optional[str] = None


@app.post("/pa10/hmac", tags=["PA10 - HMAC"])
def pa10_hmac(req: PA10HMACRequest):
    """Compute or verify the PA#10 HMAC built from the PA#8 DLP hash."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        message = bytes.fromhex(req.message_hex) if req.message_hex else (req.message or "").encode()
        hmac_impl = HMACDLP()
        trace = hmac_impl.trace(key, message)
        verified = None if req.tag_hex is None else hmac_impl.verify(key, message, bytes.fromhex(req.tag_hex))
        return {
            "message_text": message.decode("utf-8", errors="replace"),
            "message_hex": message.hex(),
            "verified": verified,
            **trace,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PA10EncryptRequest(BaseModel):
    key_hex: Optional[str] = None
    message: Optional[str] = None
    message_hex: Optional[str] = None


@app.post("/pa10/encrypt", tags=["PA10 - HMAC CCA"])
def pa10_encrypt(req: PA10EncryptRequest):
    """Encrypt with the PA#10 Encrypt-then-HMAC construction."""
    try:
        key = bytes.fromhex(req.key_hex) if req.key_hex else os.urandom(16)
        message = bytes.fromhex(req.message_hex) if req.message_hex else (req.message or "PA10 protected message").encode()
        bundle = etm_hmac_encrypt(key, message)
        tag_bytes = HMACDLP().output_bytes
        return {
            "key_hex": key.hex(),
            "message_hex": message.hex(),
            "message_text": message.decode("utf-8", errors="replace"),
            "ciphertext_hex": bundle.hex(),
            "ciphertext_body_hex": bundle[:-tag_bytes].hex(),
            "tag_hex": bundle[-tag_bytes:].hex(),
            "tag_bits": tag_bytes * 8,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PA10DecryptRequest(BaseModel):
    key_hex: str
    ciphertext_hex: str


@app.post("/pa10/decrypt", tags=["PA10 - HMAC CCA"])
def pa10_decrypt(req: PA10DecryptRequest):
    """Decrypt a PA#10 Encrypt-then-HMAC ciphertext bundle."""
    try:
        key = bytes.fromhex(req.key_hex)
        bundle = bytes.fromhex(req.ciphertext_hex)
        message = etm_hmac_decrypt(key, bundle)
        return {
            "key_hex": key.hex(),
            "ciphertext_hex": bundle.hex(),
            "message_hex": message.hex(),
            "message_text": message.decode("utf-8", errors="replace"),
        }
    except HMACCCAError as e:
        raise HTTPException(status_code=400, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class PA10CCAGameRequest(BaseModel):
    trials: int = Field(default=100, ge=10, le=2000)


@app.post("/pa10/cca_game", tags=["PA10 - HMAC CCA"])
def pa10_cca_game(req: PA10CCAGameRequest):
    """Run the PA#10 tamper-rejection experiment."""
    try:
        return cca2_hmac_game(req.trials)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa10/protection_demo", tags=["PA10 - HMAC CCA"])
def pa10_protection_demo():
    """Compare bare CPA encryption with Encrypt-then-HMAC under tampering."""
    try:
        return decrypt_then_hmac_demo()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


# ===========================================================================
# Part III Endpoints
# ===========================================================================

class RSAKeygenRequest(BaseModel):
    bits: int = Field(default=512, ge=128, le=2048)


@app.post("/pa5/rsa_keygen", tags=["PA5 - RSA"])
def rsa_keygen_endpoint(req: RSAKeygenRequest):
    """Generate an RSA key pair."""
    try:
        keys = rsa_keygen(req.bits)
        return {
            "bits": keys["bits"],
            "p_hex": hex(keys["p"]),
            "q_hex": hex(keys["q"]),
            "n_hex": hex(keys["public"]["n"]),
            "e": keys["public"]["e"],
            "d_hex": hex(keys["private"]["d"]),
            "phi_hex": hex(keys["phi"]),
            "n_bits": keys["public"]["n"].bit_length(),
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


from backend.pa5.pubkey import E_DEFAULT


class RSACryptRequest(BaseModel):
    n_hex: str
    e: int = E_DEFAULT
    d_hex: Optional[str] = None
    message: Optional[str] = None
    message_int: Optional[int] = None
    ciphertext_int: Optional[int] = None


@app.post("/pa5/rsa_encrypt", tags=["PA5 - RSA"])
def rsa_encrypt_endpoint(req: RSACryptRequest):
    """Encrypt a message with RSA public key."""
    try:
        n = int(req.n_hex, 16)
        if req.message_int is not None:
            m = req.message_int
        elif req.message:
            m = int.from_bytes(req.message.encode(), 'big')
        else:
            m = int.from_bytes(b"Hello RSA!", 'big')
        c = rsa_encrypt(m, n, req.e)
        return {
            "message_int": m,
            "message_text": m.to_bytes(max(1, (m.bit_length()+7)//8), 'big').decode('utf-8', errors='replace'),
            "ciphertext_int": c,
            "ciphertext_hex": hex(c),
            "n_hex": req.n_hex,
            "e": req.e,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa5/rsa_decrypt", tags=["PA5 - RSA"])
def rsa_decrypt_endpoint(req: RSACryptRequest):
    """Decrypt a ciphertext with RSA private key."""
    try:
        n = int(req.n_hex, 16)
        d = int(req.d_hex, 16) if req.d_hex else 0
        c = req.ciphertext_int if req.ciphertext_int is not None else 0
        m = rsa_decrypt(c, n, d)
        text = m.to_bytes(max(1, (m.bit_length()+7)//8), 'big').decode('utf-8', errors='replace')
        return {
            "ciphertext_int": c,
            "decrypted_int": m,
            "decrypted_text": text,
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class RSASignRequest(BaseModel):
    n_hex: str
    e: int = E_DEFAULT
    d_hex: str
    message: Optional[str] = "Sign this"
    message_int: Optional[int] = None


@app.post("/pa5/rsa_sign", tags=["PA5 - RSA Signatures"])
def rsa_sign_endpoint(req: RSASignRequest):
    """Sign a message and verify the signature."""
    try:
        n = int(req.n_hex, 16)
        d = int(req.d_hex, 16)
        if req.message_int is not None:
            m = req.message_int
        else:
            m = int.from_bytes(req.message.encode(), 'big')
        if m >= n:
            m = m % n
        sigma = rsa_sign(m, n, d)
        verified = rsa_verify(m, sigma, n, req.e)
        return {
            "message_int": m,
            "signature_hex": hex(sigma),
            "verified": verified,
            "description": "σ = m^d mod n; verify: m == σ^e mod n",
        }
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class RSACPARequest(BaseModel):
    bits: int = Field(default=512, ge=128, le=2048)


@app.post("/pa5/rsa_cpa_demo", tags=["PA5 - RSA Security"])
def rsa_cpa_endpoint(req: RSACPARequest):
    """Demonstrate that textbook RSA is NOT CPA-secure (deterministic)."""
    try:
        return rsa_cpa_demo(req.bits)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa5/dh_exchange", tags=["PA5 - Diffie-Hellman"])
def dh_exchange_endpoint():
    """Run a full Diffie-Hellman key exchange between Alice and Bob."""
    try:
        return dh_exchange_demo()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/pa5/dh_mitm", tags=["PA5 - DH Security"])
def dh_mitm_endpoint():
    """Demonstrate a man-in-the-middle attack on unauthenticated DH."""
    try:
        return dh_mitm_demo()
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


class AuthDHRequest(BaseModel):
    rsa_bits: int = Field(default=512, ge=128, le=2048)


@app.post("/pa5/authenticated_dh", tags=["PA5 - Authenticated DH"])
def authenticated_dh_endpoint(req: AuthDHRequest):
    """Authenticated DH: RSA signatures prevent MITM."""
    try:
        return authenticated_dh_demo(req.rsa_bits)
    except Exception as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.get("/health", tags=["Health"])
def health():
    return {"status": "ok", "project": "CS8.401 POIS — Minicrypt"}


@app.get("/", tags=["Info"])
def root():
    return {
        "project": "CS8.401 Principles of Information Security",
        "assignments": [
            "PA#1: OWF + PRG",
            "PA#2: PRF (GGM Tree)",
            "PA#3: PRP + AES Modes",
            "PA#4/PA#5 legacy MAC demos",
            "PA#5: Public-Key (RSA + DH)",
            "PA#7: Merkle-Damgard",
            "PA#8: DLP-based CRHF",
            "PA#9: Birthday Attack (Collision Finding)",
            "PA#10: HMAC + HMAC-based CCA Encryption",
        ],
        "docs": "/docs"
    }
