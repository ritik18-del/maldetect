import io
import math
import os
import re
from typing import List, Tuple

import numpy as np


BYTE_HISTOGRAM_BINS = 256


def _byte_histogram(file_bytes: bytes) -> np.ndarray:
    hist = np.zeros(BYTE_HISTOGRAM_BINS, dtype=np.float64)
    if not file_bytes:
        return hist
    arr = np.frombuffer(file_bytes, dtype=np.uint8)
    counts = np.bincount(arr, minlength=BYTE_HISTOGRAM_BINS)
    hist = counts.astype(np.float64)
    hist_sum = hist.sum()
    if hist_sum > 0:
        hist = hist / hist_sum
    return hist


def _entropy(file_bytes: bytes) -> float:
    if not file_bytes:
        return 0.0
    arr = np.frombuffer(file_bytes, dtype=np.uint8)
    counts = np.bincount(arr, minlength=BYTE_HISTOGRAM_BINS)
    probs = counts / counts.sum() if counts.sum() > 0 else counts
    # Shannon entropy in bits
    nonzero = probs[probs > 0]
    return float(-(nonzero * np.log2(nonzero)).sum())


def _string_stats(file_bytes: bytes) -> Tuple[float, float, float]:
    # Extract printable ASCII strings and compute stats
    text = re.findall(rb"[ -~]{4,}", file_bytes)
    if not text:
        return 0.0, 0.0, 0.0
    lengths = np.array([len(s) for s in text], dtype=np.float64)
    return float(lengths.mean()), float(lengths.std(ddof=0)), float(len(lengths))


def extract_features_from_bytes(file_bytes: bytes) -> Tuple[np.ndarray, List[str]]:
    hist = _byte_histogram(file_bytes)
    ent = _entropy(file_bytes)
    mean_len, std_len, num_str = _string_stats(file_bytes)
    size = float(len(file_bytes))

    features = np.concatenate([
        hist,
        np.array([ent, mean_len, std_len, num_str, size], dtype=np.float64),
    ]).astype(np.float32)

    feature_names = [f"byte_hist_{i}" for i in range(BYTE_HISTOGRAM_BINS)] + [
        "entropy",
        "strings_mean_len",
        "strings_std_len",
        "strings_count",
        "file_size",
    ]
    return features, feature_names


def get_feature_vector_length() -> int:
    return BYTE_HISTOGRAM_BINS + 5


