"""Generate reproducible, fully synthetic security-event session windows.

This dataset is simulated only. It contains no real election, voter, account,
IP-address, candidate, session-ID, or ballot data.
"""
from pathlib import Path

import numpy as np
import pandas as pd

RANDOM_SEED = 42
RECORD_COUNT = 10_000
ATTACK_FRACTION = 0.05
ATTACK_TYPES = ("brute_force", "token_replay", "bot_traffic", "credential_stuffing")
FEATURE_COLUMNS = (
    "failed_logins", "requests_per_minute", "login_attempts", "token_requests",
    "distinct_accounts_per_ip", "avg_gap_between_requests", "session_duration",
    "off_hours_flag",
)


def _bounded_normal(rng, mean, spread, lower, upper, size):
    """Draw noisy measurements and keep them inside realistic bounds."""
    return np.clip(rng.normal(mean, spread, size), lower, upper)


def _make_records(rng, count, attack_type):
    """Make a normal or attack group; distributions intentionally overlap."""
    # Values start from ordinary activity. Each attack shifts only a few signals,
    # so there is noise and overlap instead of a perfect rule-based separation.
    profiles = {
        "failed_logins": (0.7, 1.5, 0, 12),
        "requests_per_minute": (18, 12, 1, 120),
        "login_attempts": (1.5, 1.4, 0, 12),
        "token_requests": (5, 3, 0, 30),
        "distinct_accounts_per_ip": (1.2, 0.7, 1, 8),
        "avg_gap_between_requests": (8, 7, 0.2, 60),
        "session_duration": (9, 7, 0.2, 90),
    }
    shifts = {
        "brute_force": {"failed_logins": (7, 5), "login_attempts": (8, 5)},
        "token_replay": {"token_requests": (18, 12), "avg_gap_between_requests": (3, 3)},
        "bot_traffic": {"requests_per_minute": (72, 38), "avg_gap_between_requests": (2.5, 2)},
        "credential_stuffing": {
            "failed_logins": (5, 4), "distinct_accounts_per_ip": (6, 3), "login_attempts": (6, 4)
        },
    }
    if attack_type != "normal":
        for feature, (mean, spread) in shifts[attack_type].items():
            lower, upper = profiles[feature][2:]
            profiles[feature] = (mean, spread, lower, upper)

    records = {}
    for feature, (mean, spread, lower, upper) in profiles.items():
        values = _bounded_normal(rng, mean, spread, lower, upper, count)
        if feature in {"failed_logins", "login_attempts", "token_requests", "distinct_accounts_per_ip"}:
            values = np.rint(values).astype(int)
        records[feature] = values

    # Some normal and attack sessions happen outside typical hours.
    off_hours_probability = 0.24 if attack_type == "normal" else 0.34
    records["off_hours_flag"] = rng.binomial(1, off_hours_probability, count)
    records["attack_type"] = attack_type
    records["label"] = 0 if attack_type == "normal" else 1
    return pd.DataFrame(records)


def generate_dataset(output_path=None):
    """Create the CSV beside this script using a fixed NumPy random seed."""
    rng = np.random.default_rng(RANDOM_SEED)
    attack_count = int(RECORD_COUNT * ATTACK_FRACTION)
    normal_count = RECORD_COUNT - attack_count
    per_type = attack_count // len(ATTACK_TYPES)

    groups = [_make_records(rng, normal_count, "normal")]
    groups.extend(_make_records(rng, per_type, kind) for kind in ATTACK_TYPES)
    dataset = pd.concat(groups, ignore_index=True)
    dataset = dataset.iloc[rng.permutation(len(dataset))].reset_index(drop=True)

    # Explicit column order makes the generated file easy to inspect and use.
    dataset = dataset.loc[:, [*FEATURE_COLUMNS, "attack_type", "label"]]
    target = Path(output_path) if output_path else Path(__file__).resolve().with_name("dataset.csv")
    dataset.to_csv(target, index=False, float_format="%.8f", lineterminator="\n")
    print(f"Generated {len(dataset):,} simulated records at {target}")
    print("Label counts:", dataset["label"].value_counts().sort_index().to_dict())
    print("Attack types:", dataset["attack_type"].value_counts().sort_index().to_dict())
    return dataset


if __name__ == "__main__":
    generate_dataset()
