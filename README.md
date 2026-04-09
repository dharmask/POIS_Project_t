# CS8.401 POIS Project

This repository contains the POIS assignment explorer backend and React demo.  
PA #8 is implemented as a DLP-based collision-resistant hash that reuses the existing PA #7 Merkle-Damgard framework, and PA #9 adds end-to-end birthday-attack experiments on top of it.

## PA #8

- Core module: `backend/pa8/dlp_hash.py`
- Compression function: `h(x, y) = g^x * h_hat^y mod p`
- Hash construction: existing `backend/pa7/merkle_damgard.py` with PA #8 compression plugged in
- Output modes: full digest, plus truncated 8, 12, and 16-bit digests
- Demo support:
  - birthday collision hunt on truncated toy output
  - toy compression-collision reduction check

## PA #9

- Core module: `backend/pa9/birthday_attack.py`
- Algorithms:
  - naive birthday attack with a hash table
  - Floyd cycle-finding collision search with O(1) extra space
- Experiments:
  - own weak toy hash for `n in {8, 12, 16}`
  - truncated PA #8 DLP hash attack at `n = 16`
  - empirical birthday curve for `n in {8, 10, 12, 14, 16}`
  - MD5 / SHA-1 collision-cost context
  - interactive live demo page in the frontend

## API

- `POST /pa8/hash`
- `POST /pa8/hash_truncated`
- `POST /pa8/collision_demo`
- `POST /pa9/attack`
- `POST /pa9/compare`
- `POST /pa9/curve`
- `POST /pa9/live_demo`
- `POST /pa9/context`

Run the backend:

```powershell
.\venv\Scripts\python.exe -m uvicorn backend.api.main:app --reload --port 8000
```

## Frontend

The React explorer now includes dedicated PA #8 and PA #9 pages with:

- message input
- full or truncated hash output
- toy/full parameter toggle for hashing
- collision hunt for 8, 12, and 16-bit truncation
- live birthday attack animation
- algorithm-comparison tables
- empirical collision-probability curves
- MD5 / SHA-1 cost estimates

Run the frontend:

```powershell
cd frontend
npm run dev
```

## Tests

Backend:

```powershell
.\venv\Scripts\python.exe -m pytest tests -v
```

Frontend:

```powershell
cd frontend
npm test
npm run build
npm run lint
```

## Notes

- PA #8 uses only built-in big integers, modular arithmetic, and OS randomness.
- No external cryptographic libraries are used for the hash construction.
- The default hash uses a fixed full safe-prime subgroup for deterministic outputs.
- Collision hunting uses a fixed toy subgroup so the demo completes quickly.
