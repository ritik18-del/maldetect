import argparse
import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.models.train import train_model, ALGORITHMS


def main():
    parser = argparse.ArgumentParser(description="Train MalDetect model")
    group = parser.add_mutually_exclusive_group()
    group.add_argument("--from-csv", dest="csv_path", help="Path to features CSV with 'label' column")
    group.add_argument("--from-samples", action="store_true", help="Use files in data/samples/")
    parser.add_argument("--algo", choices=list(ALGORITHMS.keys()), default="rf", help="Which algorithm to train")
    parser.add_argument("--all", action="store_true", help="Train all supported algorithms")
    args = parser.parse_args()

    csv_path = args.csv_path if args.csv_path else None
    results = train_model(csv_path=csv_path, algo=args.algo, train_all=args.all)
    for res in results:
        print(f"\n=== {res.algo.upper()} ===")
        print("Model saved to:", res.model_path)
        print("\nClassification report:\n")
        print(res.report)


if __name__ == "__main__":
    main()


