import pandas as pd
from pathlib import Path


BASE_DIR = Path(__file__).resolve().parent.parent

FEATURE_PATH = BASE_DIR / "data" / "normal" / "normal_features.csv"
BASELINE_PATH = BASE_DIR / "data" / "normal" / "normal_baseline.csv"


def create_baseline():

    print("Loading normal traffic features...")

    if not FEATURE_PATH.exists():
        print("ERROR: normal_features.csv not found.")
        print("Run feature_extraction.py first.")
        return

    df = pd.read_csv(FEATURE_PATH)

    # Calculate baseline statistics
    baseline = df.mean(numeric_only=True).to_frame().T

    baseline.to_csv(BASELINE_PATH, index=False)

    print("\n========== NORMAL BASELINE ==========")

    for column in baseline.columns:

        value = baseline[column].iloc[0]

        print(f"{column:30}: {value:.2f}")

    print("\nBaseline saved to:")
    print(BASELINE_PATH)


if __name__ == "__main__":
    create_baseline()