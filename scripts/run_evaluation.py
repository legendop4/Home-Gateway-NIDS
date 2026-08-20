"""
Standalone CLI entrypoint for running NIDS evaluation harness and ablation benchmarks.
"""

import argparse
from nids.ml.evaluate import evaluate_all


def main():
    parser = argparse.ArgumentParser(description="Run Home-Gateway NIDS Evaluation and Ablation Benchmark")
    parser.add_argument("--weights", type=str, default="models/transformer_recon.pt", help="Path to Transformer weights")
    parser.add_argument("--threshold", type=float, default=0.70, help="Decision threshold for reconnaissance")
    parser.add_argument("--pcaps", type=str, default="data/pcaps", help="Directory containing lab PCAPs")
    parser.add_argument("--out", type=str, default="data/evaluation_report.json", help="Path to output JSON report")
    args = parser.parse_args()

    evaluate_all(
        weights_path=args.weights,
        threshold=args.threshold,
        pcap_dir=args.pcaps,
        output_report_path=args.out,
    )


if __name__ == "__main__":
    main()
