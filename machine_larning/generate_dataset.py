"""Generate a SYNTHETIC e-voting session-window dataset (simulated, fixed seed).

Every row is simulated. Nothing here comes from real voters or real attacks.
Run:  python machine_larning/generate_dataset.py
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

import numpy as np
import pandas as pd

from machine_larning import config

STEALTH_SHARE = 0.20   # share of attacks that are "low and slow" and overlap normal behaviour
HARD_NORMAL_SHARE = 0.10  # share of normal rows that look suspicious (forgot password, shared Wi-Fi, ...)


def _lognormal_noise(rng, n, sigma):
    return rng.lognormal(0.0, sigma, n)


def _gap(rng, rpm, sigma):
    """Average gap (seconds) between requests ~ 60 / rpm with jitter. Small sigma = evenly spaced."""
    return np.clip(60.0 / np.maximum(rpm, 0.5) * _lognormal_noise(rng, len(rpm), sigma), 0.05, 300)


def _normal(rng, n):
    attempts = rng.choice([1, 2], size=n, p=[0.80, 0.20])
    failed = np.minimum(rng.binomial(attempts, 0.18), 2)
    rpm = np.clip(rng.gamma(3.0, 2.0, n), 0.5, 40)
    token = rng.choice([0, 1, 2], size=n, p=[0.35, 0.60, 0.05])
    distinct = rng.choice([1, 2, 3, 4], size=n, p=[0.92, 0.06, 0.015, 0.005])
    duration = np.clip(rng.lognormal(np.log(240), 0.6, n), 20, 3600)
    off = rng.binomial(1, 0.08, n)

    # Hard normals: legitimate but unusual (overlap with attacks)
    hard = rng.random(n) < HARD_NORMAL_SHARE
    kind = rng.integers(0, 3, n)
    m = hard & (kind == 0)  # forgot password
    attempts[m] = rng.integers(3, 7, m.sum())
    failed[m] = np.minimum(rng.binomial(attempts[m], 0.6), attempts[m])
    m = hard & (kind == 1)  # power user / heavy page refresh
    rpm[m] = rng.uniform(25, 60, m.sum())
    token[m] = rng.integers(2, 5, m.sum())
    m = hard & (kind == 2)  # shared campus Wi-Fi
    distinct[m] = rng.integers(3, 6, m.sum())

    gap = _gap(rng, rpm, 0.5)
    return pd.DataFrame({
        "failed_logins": failed, "requests_per_minute": rpm, "login_attempts": attempts,
        "token_requests": token, "distinct_accounts_per_ip": distinct,
        "avg_gap_between_requests": gap, "session_duration": duration, "off_hours_flag": off,
    })


def _attack(rng, n, kind):
    stealth = rng.random(n) < STEALTH_SHARE
    u = lambda lo, hi, slo, shi: np.where(stealth, rng.uniform(slo, shi, n), rng.uniform(lo, hi, n))
    i = lambda lo, hi, slo, shi: np.where(stealth, rng.integers(slo, shi, n), rng.integers(lo, hi, n))
    duration = np.clip(rng.lognormal(np.log(150), 0.7, n), 10, 3600)
    off = rng.binomial(1, 0.35, n)
    token = rng.integers(0, 2, n)
    distinct = rng.choice([1, 2], size=n, p=[0.85, 0.15])
    gap_sigma = 0.35

    if kind == "brute_force":
        failed = i(6, 41, 3, 7)
        attempts = failed + rng.integers(0, 2, n)
        rpm = u(12, 60, 4, 20)
    elif kind == "token_replay":
        attempts = rng.integers(1, 3, n)
        failed = np.minimum(rng.integers(0, 3, n), attempts)
        token = i(6, 31, 3, 7)
        rpm = u(10, 50, 5, 20)
    elif kind == "bot_traffic":
        attempts = rng.integers(1, 4, n)
        failed = np.minimum(rng.integers(0, 4, n), attempts)
        token = rng.integers(0, 4, n)
        rpm = u(90, 300, 40, 90)
        gap_sigma = 0.08  # evenly spaced requests
        duration = rng.uniform(30, 600, n)
    elif kind == "credential_stuffing":
        distinct = i(6, 41, 3, 7)
        attempts = distinct + rng.integers(0, 6, n)
        failed = np.maximum((attempts * rng.uniform(0.7, 0.98, n)).astype(int), 1)
        rpm = u(20, 90, 8, 25)
    else:
        raise ValueError(kind)

    return pd.DataFrame({
        "failed_logins": failed, "requests_per_minute": rpm, "login_attempts": attempts,
        "token_requests": token, "distinct_accounts_per_ip": distinct,
        "avg_gap_between_requests": _gap(rng, rpm, gap_sigma), "session_duration": duration,
        "off_hours_flag": off,
    })


def generate(n_rows=12000, attack_fraction=0.05, seed=config.RANDOM_SEED, missing_rate=0.015):
    rng = np.random.default_rng(seed)
    n_attack = int(round(n_rows * attack_fraction))
    n_normal = n_rows - n_attack

    normal = _normal(rng, n_normal)
    normal["attack_type"] = "none"

    per_type = np.full(len(config.ATTACK_TYPES), n_attack // len(config.ATTACK_TYPES))
    per_type[: n_attack % len(config.ATTACK_TYPES)] += 1
    parts = []
    for kind, k in zip(config.ATTACK_TYPES, per_type):
        a = _attack(rng, int(k), kind)
        a["attack_type"] = kind
        parts.append(a)

    df = pd.concat([normal] + parts, ignore_index=True)

    # Sensor noise on continuous features (creates extra overlap)
    for col in ("requests_per_minute", "avg_gap_between_requests", "session_duration"):
        df[col] = df[col] * rng.lognormal(0.0, 0.08, len(df))
    df["requests_per_minute"] = df["requests_per_minute"].clip(lower=0.1).round(2)
    df["avg_gap_between_requests"] = df["avg_gap_between_requests"].clip(lower=0.05).round(2)
    df["session_duration"] = df["session_duration"].round(1)
    for col in ("failed_logins", "login_attempts", "token_requests",
                "distinct_accounts_per_ip", "off_hours_flag"):
        df[col] = df[col].astype(int)

    df["label"] = (df["attack_type"] != "none").astype(int)
    df = df.sample(frac=1.0, random_state=seed).reset_index(drop=True)

    # Missing values (sensor gaps / dropped log lines)
    for col in ("requests_per_minute", "avg_gap_between_requests", "session_duration"):
        df.loc[rng.random(len(df)) < missing_rate, col] = np.nan

    df.insert(0, "session_id", [f"SIM-{i:06d}" for i in range(1, len(df) + 1)])
    df["data_source"] = "SIMULATED"
    return df


def main():
    df = generate()
    df.to_csv(config.DATASET_PATH, index=False)
    print(config.SIM_NOTICE)
    print(f"Saved {len(df):,} rows to {config.DATASET_PATH}")
    print(f"Attack share: {df['label'].mean():.2%}")
    print(df["attack_type"].value_counts().to_string())


if __name__ == "__main__":
    main()
