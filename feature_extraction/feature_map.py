import sys
from pathlib import Path
import argparse

import cv2
import numpy as np
from skimage import morphology

# Pipeline works like this:
# 1. Load image as grayscale
# 2. Segment palm area
# 3. Correct illumination & exposure issues
# 4. (Optional) Enhance illumination in certain areas on correct img to make vessels more obvious
# 5. Single-scale vessel response with Gabor filter
# 6. Multi-scale vessel response to check for different size veins
# 7. Enhance feature map, send to post processing unit
# 8. Generate a red overlay to get good visual of what the pipeline sees as "veins"

def load_grayscale(path:str):
    """
    Loads image in grayscale, returns as a **UINT8 array**.
    
    :param path: image path
    :type path: str
    """
    bw = cv2.imread(path, cv2.IMREAD_GRAYSCALE)
    if bw is None:
        raise RuntimeError(f"check path: {path}")
    return bw

def segmentation_hand_mask(bw_img):
    """
    Segment the image of the hand so that we draw on an extract features from only the palm (here is calculated as simply the brightest component. Probably have to make this more sophisticated down the line).

    1) Blur + Otsu threshold
    2) Find biggest continuous shape
    3) Morpho cleanup
    4) Pad region with extra space to avoid background getting considered for features. 
    
    :param bw_img: grayscale image
    """

    
