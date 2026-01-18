#!/usr/bin/env python3
"""
Test/verify a palmprint against an enrolled template.
"""
import argparse
from pathlib import Path
import numpy as np
from enroll import cosine_sim
from feature_vector import _load_u8_gray, _ensure_mask, extract_feature_vector


def main():
    parser = argparse.ArgumentParser(description="Test palmprint verification against enrolled template")
    parser.add_argument("template", type=Path, help="Path to enrolled template (.npy)")
    parser.add_argument("test_image", type=Path, help="Path to test feature map (raw_response.png)")
    parser.add_argument("--mask", type=Path, default=None, help="Path to safe_mask (if not provided, will try to find it)")
    parser.add_argument("--grid", type=int, default=32, help="Grid size for pooling (default 32)")
    parser.add_argument("--pad", type=int, default=8, help="Padding when cropping to mask bbox (default 8)")
    parser.add_argument("--threshold", type=float, default=0.3, help="Similarity threshold for match (default 0.3)")
    args = parser.parse_args()
    
    # Load template
    template = np.load(str(args.template))
    print(f"Loaded template: shape={template.shape}, norm={np.linalg.norm(template):.4f}")
    
    # Load test feature map
    test_map = _load_u8_gray(args.test_image)
    
    # Load or find mask
    if args.mask is not None:
        test_mask = _ensure_mask(_load_u8_gray(args.mask))
    else:
        # Try to find mask in same directory
        test_dir = args.test_image.parent
        test_stem = args.test_image.stem.replace('_raw_response', '')
        mask_path = test_dir / f"{test_stem}_02_safe_mask.png"
        if mask_path.exists():
            test_mask = _ensure_mask(_load_u8_gray(mask_path))
            print(f"Found mask: {mask_path}")
        else:
            raise RuntimeError(f"Could not find mask. Please specify --mask or ensure {mask_path} exists")
    
    # Extract feature vector from test image
    test_vec = extract_feature_vector(test_map, test_mask, grid_size=args.grid, pad=args.pad)
    print(f"Extracted test vector: shape={test_vec.shape}, norm={np.linalg.norm(test_vec):.4f}")
    
    # Compute similarity
    similarity = cosine_sim(template, test_vec)
    print(f"\nSimilarity: {similarity:.4f}")
    print(f"Threshold: {args.threshold:.4f}")
    
    # Decision
    if similarity >= args.threshold:
        print(f"✓ MATCH (similarity {similarity:.4f} >= threshold {args.threshold:.4f})")
        return 0
    else:
        print(f"✗ NO MATCH (similarity {similarity:.4f} < threshold {args.threshold:.4f})")
        return 1


if __name__ == "__main__":
    exit(main())
