import argparse
from pathlib import Path
from .analyzer import analyze_responses, build_report

def main():
    parser = argparse.ArgumentParser(description="Compare two captured HTTP responses (no network requests are sent).")
    parser.add_argument("response_a", help="Path to captured response A")
    parser.add_argument("response_b", help="Path to captured response B")
    parser.add_argument("--report", help="Optional Markdown report output path")
    args = parser.parse_args()
    a = Path(args.response_a).read_text(encoding="utf-8", errors="replace")
    b = Path(args.response_b).read_text(encoding="utf-8", errors="replace")
    result = analyze_responses(a, b)
    print(f"Assessment: {result['assessment']}")
    print(f"Status: {result['status_a']} vs {result['status_b']}")
    print(f"Body similarity: {result['similarity_percent']}%")
    for observation in result["observations"]:
        print(f"- {observation}")
    if args.report:
        Path(args.report).write_text(build_report(result), encoding="utf-8")
        print(f"Report saved to: {args.report}")

if __name__ == "__main__":
    main()
