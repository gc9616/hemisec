#!/usr/bin/env python3
import argparse
import base64
import json
from pathlib import Path

import cv2
import numpy as np


def _load_u8_gray(path: Path) -> np.ndarray:
    img = cv2.imread(str(path), cv2.IMREAD_GRAYSCALE)
    if img is None:
        raise RuntimeError(f"Could not read image: {path}")
    return img


def _ensure_mask(mask_u8: np.ndarray) -> np.ndarray:
    if mask_u8.dtype != np.uint8:
        mask_u8 = np.clip(mask_u8, 0, 255).astype(np.uint8)
    return (mask_u8 > 0).astype(np.uint8) * 255


def _mask_from_feature_map(feature_u8: np.ndarray, thresh: int = 1) -> np.ndarray:
    # fallback if you don't have safe_mask: "nonzero region" + erosion to avoid boundary junk
    mask = (feature_u8 > thresh).astype(np.uint8) * 255
    if cv2.countNonZero(mask) == 0:
        return np.ones_like(feature_u8, dtype=np.uint8) * 255
    mask = cv2.morphologyEx(mask, cv2.MORPH_CLOSE,
                            cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (15, 15)),
                            iterations=1)
    mask = cv2.erode(mask, cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (11, 11)), iterations=1)
    return mask


def _crop_to_mask(img_u8: np.ndarray, mask_u8: np.ndarray, pad: int = 8):
    ys, xs = np.where(mask_u8 > 0)
    if xs.size == 0 or ys.size == 0:
        return img_u8, mask_u8
    h, w = img_u8.shape
    x0 = max(int(xs.min()) - pad, 0)
    x1 = min(int(xs.max()) + pad + 1, w)
    y0 = max(int(ys.min()) - pad, 0)
    y1 = min(int(ys.max()) + pad + 1, h)
    return img_u8[y0:y1, x0:x1], mask_u8[y0:y1, x0:x1]


def extract_feature_vector(feature_map_u8: np.ndarray,
                           mask_u8: np.ndarray,
                           grid_size: int = 256,
                           pad: int = 8,
                           eps: float = 1e-9) -> np.ndarray:
    """
    Stable baseline embedding:
      mask -> crop -> resize -> z-score inside mask -> flatten -> L2 normalize
    
    NOTE: Default grid_size changed from 32 to 256 (2024-01-18)
    - 32x32 = 1,024 elements (compact, fast, good for coarse features)
    - 256x256 = 65,536 elements (high detail, preserves fine spatial structure)
    
    Trade-offs:
    - Larger vectors preserve more spatial detail and fine-grained vein patterns
    - Better discrimination for similar palms but more sensitive to alignment/rotation
    - 64x more memory and slower cosine similarity computation
    - May require different similarity thresholds for matching
    """
    mask_u8 = _ensure_mask(mask_u8)
    fm = cv2.bitwise_and(feature_map_u8, feature_map_u8, mask=mask_u8)

    fm_crop, mask_crop = _crop_to_mask(fm, mask_u8, pad=pad)

    fm_small = cv2.resize(fm_crop, (grid_size, grid_size), interpolation=cv2.INTER_AREA)
    mask_small = cv2.resize(mask_crop, (grid_size, grid_size), interpolation=cv2.INTER_NEAREST)

    fm_small = fm_small.astype(np.float32)
    fm_small[mask_small == 0] = 0.0

    vals = fm_small[mask_small > 0]
    if vals.size > 0:
        m = float(vals.mean())
        s = float(vals.std()) + eps
        fm_small = (fm_small - m) / s
        fm_small[mask_small == 0] = 0.0

    vec = fm_small.flatten().astype(np.float32)
    n = float(np.linalg.norm(vec)) + eps
    return vec / n


def vector_to_b64_json(vec: np.ndarray,
                       algorithm: str = "palmvein_v1",
                       dtype: str = "float32") -> dict:
    vec = vec.astype(np.float32, copy=False)
    raw_bytes = vec.tobytes()
    b64_vector = base64.b64encode(raw_bytes).decode("utf-8")
    return {
        "vector": b64_vector,
        "dtype": dtype,
        "length": int(vec.size),
        "algorithm": algorithm,
    }


def main():
    parser = argparse.ArgumentParser(description="Extract feature vector from enhanced feature map image")
    parser.add_argument("feature_map", type=Path, help="Path to enhanced feature map image (grayscale PNG)")
    parser.add_argument("--mask", type=Path, default=None, help="Optional safe_mask image path (uint8 0/255)")
    parser.add_argument("--grid", type=int, default=256, help="Grid size for pooling (default 256, was 32)")
    parser.add_argument("--pad", type=int, default=8, help="Padding when cropping to mask bbox (default 8)")
    parser.add_argument("--algorithm", type=str, default="palmvein_v1", help="Algorithm name in JSON")
    args = parser.parse_args()

    feature_u8 = _load_u8_gray(args.feature_map)

    if args.mask is not None:
        mask_u8 = _ensure_mask(_load_u8_gray(args.mask))
    else:
        mask_u8 = _mask_from_feature_map(feature_u8)

    vec = extract_feature_vector(feature_u8, mask_u8, grid_size=args.grid, pad=args.pad)
    payload = vector_to_b64_json(vec, algorithm=args.algorithm)
    print(json.dumps(payload))


if __name__ == "__main__":
    main()
