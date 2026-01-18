#!/usr/bin/env python3
import argparse
import json
import base64
from pathlib import Path

import cv2
import numpy as np

from feature_vector import _load_u8_gray, _ensure_mask, extract_feature_vector, vector_to_b64_json


def cosine_sim(a: np.ndarray, b: np.ndarray, eps: float = 1e-9) -> float:
    return float(np.dot(a, b) / ((np.linalg.norm(a) * np.linalg.norm(b)) + eps))


def build_template(vectors: list[np.ndarray], keep_top_frac: float = 0.8) -> tuple[np.ndarray, np.ndarray, np.ndarray]:
    V = np.stack(vectors, axis=0).astype(np.float32)
    center = V.mean(axis=0)
    center /= (np.linalg.norm(center) + 1e-9)

    sims = np.array([cosine_sim(v, center) for v in V], dtype=np.float32)
    k = max(1, int(np.ceil(len(sims) * keep_top_frac)))
    keep_idx = np.argsort(-sims)[:k]

    tmpl = V[keep_idx].mean(axis=0)
    tmpl /= (np.linalg.norm(tmpl) + 1e-9)
    return tmpl, sims, keep_idx


def main():
    parser = argparse.ArgumentParser(description="Enroll a palm vein template from multiple feature maps + masks")
    parser.add_argument("--maps", nargs="+", type=Path, required=True, help="List of feature map images (raw_response.png)")
    parser.add_argument("--masks", nargs="+", type=Path, required=True, help="List of safe_mask images (same order)")
    parser.add_argument("--grid", type=int, default=256, help="Grid size for pooling (default 256, was 32)")
    parser.add_argument("--pad", type=int, default=8, help="Padding when cropping to mask bbox (default 8)")
    parser.add_argument("--keep", type=float, default=0.8, help="Keep top fraction of captures (default 0.8)")
    parser.add_argument("--save", type=Path, default=None, help="Path to save template (.npy)")
    parser.add_argument("--print-json", action="store_true", help="Print base64 JSON payload")
    parser.add_argument("--algorithm", type=str, default="palmvein_v1", help="Algorithm label for JSON")
    args = parser.parse_args()

    if len(args.maps) != len(args.masks):
        raise RuntimeError("maps and masks must be same length and same order")

    vecs = []
    for fmap_path, mask_path in zip(args.maps, args.masks):
        fmap = _load_u8_gray(fmap_path)
        mask = _ensure_mask(_load_u8_gray(mask_path))

        # guard: reject tiny masks
        if cv2.countNonZero(mask) < 0.02 * mask.size:
            continue

        v = extract_feature_vector(fmap, mask, grid_size=args.grid, pad=args.pad)
        vecs.append(v)

    if len(vecs) < 5:
        raise RuntimeError(f"Too few usable captures after filtering: {len(vecs)}")

    tmpl, sims, keep_idx = build_template(vecs, keep_top_frac=args.keep)

    if args.save is not None:
        args.save.parent.mkdir(parents=True, exist_ok=True)
        np.save(str(args.save), tmpl)

    if args.print_json:
        payload = vector_to_b64_json(tmpl, algorithm=args.algorithm)
        print(json.dumps(payload))

    print(f"enrolled={len(vecs)} kept={len(keep_idx)} sim_min={float(sims.min()):.3f} sim_med={float(np.median(sims)):.3f} sim_max={float(sims.max()):.3f}")


if __name__ == "__main__":
    main()
