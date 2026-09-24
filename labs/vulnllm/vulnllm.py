#!/usr/bin/env python3
"""
VulnLLM - a deliberately vulnerable LLM lab
OWASP LLM Top 10 attack & defense practice.

Usage:
    python vulnllm.py                          # Main menu
    python vulnllm.py --challenge 1            # Challenge 1, interactive
    python vulnllm.py --challenge 1 --auto     # Challenge 1, automated attack
    python vulnllm.py --all --auto             # Every challenge, automated
    python vulnllm.py --challenge 1 -d medium  # Medium difficulty
    python vulnllm.py --scoreboard             # Scoreboard
"""

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

# Add the project root to the path
sys.path.insert(0, str(Path(__file__).parent))
# tools/_console.make_output_safe() needs tools/ on the path -- vulnllm.py
# lives under labs/vulnllm/, two levels below the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "tools"))

from _console import make_output_safe  # noqa: E402
from challenges import ALL_CHALLENGES
from config import (
    C_BOLD,
    C_CYAN,
    C_DIM,
    C_GREEN,
    C_MAGENTA,
    C_RED,
    C_RESET,
    C_YELLOW,
    DIFFICULTY_MAP,
    Difficulty,
)

BANNER = f"""
{C_MAGENTA}{C_BOLD}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗     ██╗     ███╗   ███╗
 ██║   ██║██║   ██║██║     ████╗  ██║██║     ██║     ████╗ ████║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║██║     ██║     ██╔████╔██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║     ██║     ██║╚██╔╝██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗███████╗██║ ╚═╝ ██║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝     ╚═╝
{C_RESET}
{C_BOLD}  OWASP LLM Top 10 -- Attack & Defense Lab{C_RESET}
{C_DIM}  v0.3 | Mock or any LLM | 10 challenges | 193 attacks{C_RESET}
"""


def print_menu():
    """Main menu."""
    print(BANNER)
    print(f"  {C_BOLD}CHALLENGES:{C_RESET}\n")

    for ch_class in ALL_CHALLENGES:
        ch = ch_class()
        print(f"    {C_CYAN}{ch.id:2d}.{C_RESET} [{ch.owasp_id}] {ch.name}")
        print(f"        {C_DIM}{ch.description}{C_RESET}")

    print(f"\n  {C_BOLD}DIFFICULTY LEVELS:{C_RESET}")
    print(f"    {C_GREEN}easy{C_RESET}   -- No defenses; learn the basic techniques")
    print(f"    {C_YELLOW}medium{C_RESET} -- Simple filters; learn the bypass techniques")
    print(f"    {C_RED}hard{C_RESET}   -- Layered defense; a real-world scenario")

    print(f"\n  {C_BOLD}REAL MODEL (--provider <p> --model <m>):{C_RESET}")
    print("    Any provider: openai, openai-compatible, ollama, anthropic, gemini, http.")
    print("    Keys come from the environment (OPENAI_API_KEY, ANTHROPIC_API_KEY, GEMINI_API_KEY).")

    print(f"\n  {C_BOLD}COMMANDS:{C_RESET}")
    print(f"    {C_DIM}Mock (default):{C_RESET}")
    print("    python vulnllm.py --challenge <N>              Interactive mode")
    print("    python vulnllm.py --challenge <N> --auto       Automated attack")
    print("    python vulnllm.py --all --auto -d medium       Every challenge in medium mode")
    print(f"    {C_DIM}Real model:{C_RESET}")
    print("    python vulnllm.py -c 1 --provider ollama --model <m>         CH01 interactive")
    print("    python vulnllm.py -c 1 -a --provider openai --model <m>      CH01 automated")
    print("    python vulnllm.py --all -a --provider anthropic --model <m>  Every challenge")
    print(f"    {C_DIM}Other:{C_RESET}")
    print("    python vulnllm.py --scoreboard                 Scoreboard")
    print()


def run_interactive(challenge):
    """Interactive chat mode."""
    challenge.print_banner()

    print(f"\n  {C_CYAN}Interactive mode{C_RESET} -- try attacking the chatbot.")
    print(f"  {C_DIM}Commands: 'quit' (exit), 'attacks' (list the ready-made attacks),")
    print(f"           'info' (defense info), 'score' (score){C_RESET}\n")

    while True:
        try:
            user_input = input(f"  {C_GREEN}attack>{C_RESET} ")
        except (KeyboardInterrupt, EOFError):
            print("\n  Exiting.")
            break

        if not user_input.strip():
            continue

        cmd = user_input.strip().lower()

        if cmd in ("quit", "exit", "q", "cik"):
            break

        elif cmd == "attacks":
            print(f"\n  {C_BOLD}Ready-made attack techniques:{C_RESET}")
            for i, tech in enumerate(challenge.get_attack_techniques(), 1):
                sev_color = C_RED if tech["severity"] == "CRITICAL" else C_YELLOW if tech["severity"] == "HIGH" else C_CYAN
                print(f"    {i}. {sev_color}[{tech['severity']}]{C_RESET} {tech['name']}")
                print(f"       {C_DIM}Payload: {tech['payload'][:70]}{C_RESET}")
                print(f"       {C_DIM}Explanation: {tech['explanation']}{C_RESET}")
            print(f"\n  {C_DIM}Type a number to use one (e.g. '1'), or enter your own payload.{C_RESET}\n")
            continue

        elif cmd == "info":
            print(f"\n  {C_BOLD}Defense info:{C_RESET} {challenge.get_defense_info()}")
            print(f"  {C_BOLD}Goal:{C_RESET} {challenge.objective}\n")
            continue

        elif cmd == "score":
            print(f"\n  {C_BOLD}Score:{C_RESET} {challenge.state.score} points")
            print(f"  {C_BOLD}Successful attacks:{C_RESET} {len(challenge.state.successful_attacks)}")
            print(f"  {C_BOLD}Blocked:{C_RESET} {len(challenge.state.blocked_attacks)}\n")
            continue

        # Pick a ready-made attack by number
        if cmd.isdigit():
            idx = int(cmd) - 1
            techniques = challenge.get_attack_techniques()
            if 0 <= idx < len(techniques):
                user_input = techniques[idx]["payload"]
                print(f"  {C_DIM}Payload: {user_input}{C_RESET}")
            else:
                print(f"  {C_RED}Invalid number. Choose between 1 and {len(techniques)}.{C_RESET}")
                continue

        # Chat
        response = challenge.chat(user_input)
        success = challenge.check_success(response.content)

        if response.blocked:
            print(f"\n  {C_RED}[BLOCKED]{C_RESET} {response.content}\n")
        elif success:
            print(f"\n  {C_GREEN}[SUCCESS!]{C_RESET} {response.content}\n")
            print(f"  {C_GREEN}+{challenge.state.score} points earned!{C_RESET}\n")
        else:
            print(f"\n  {C_YELLOW}[ANSWERED]{C_RESET} {response.content}\n")


def run_auto(challenge):
    """Automated attack mode."""
    challenge.print_banner()

    print(f"\n  {C_MAGENTA}Automated attack mode{C_RESET} -- trying every technique...\n")

    results = challenge.run_all_attacks()

    for result in results:
        challenge.print_attack_result(result)

    challenge.print_summary(results)
    return challenge.get_report(results)


def run_all_auto(difficulty: Difficulty, target=None):
    """Run every challenge automatically."""
    print(BANNER)
    backend_label = f" | {getattr(target, 'model', type(target).__name__)}" if target is not None else " | Mock"
    print(f"  {C_MAGENTA}{C_BOLD}ALL CHALLENGES -- {difficulty.name} MODE{backend_label}{C_RESET}\n")

    all_reports = []
    total_score = 0
    total_success = 0
    total_attacks = 0

    for ch_class in ALL_CHALLENGES:
        challenge = ch_class(difficulty=difficulty, target=target)
        report = run_auto(challenge)
        all_reports.append(report)
        total_score += report["score"]
        total_success += report["successful"]
        total_attacks += report["total_attacks"]
        print()

    # Overall summary
    print(f"\n{'=' * 65}")
    print(f"{C_BOLD}{C_MAGENTA}  OVERALL RESULT TABLE{C_RESET}")
    print(f"{'=' * 65}")
    print(f"  Difficulty:         {difficulty.name}")
    print(f"  Total challenges:   {len(ALL_CHALLENGES)}")
    print(f"  Total attacks:      {total_attacks}")
    print(f"  {C_GREEN}Succeeded:          {total_success}/{total_attacks}{C_RESET}")
    print(f"  {C_BOLD}Total score:        {total_score}{C_RESET}")

    print(f"\n  {C_BOLD}By challenge:{C_RESET}")
    for r in all_reports:
        status = f"{C_GREEN}PASS{C_RESET}" if r["successful"] > 0 else f"{C_RED}BLOCKED{C_RESET}"
        print(f"    #{r['challenge_id']:2d} [{r['owasp_id']}] {r['challenge_name']:<35} "
              f"{r['successful']}/{r['total_attacks']} attacks  {status}")

    print(f"\n{'=' * 65}")

    # Save the report
    report_dir = Path(__file__).parent / "reports"
    report_dir.mkdir(exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    report_path = report_dir / f"report_{difficulty.label}_{timestamp}.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump({
            "timestamp": timestamp,
            "difficulty": difficulty.label,
            "total_score": total_score,
            "total_success": total_success,
            "total_attacks": total_attacks,
            "challenges": all_reports,
        }, f, ensure_ascii=False, indent=2)
    print(f"\n  {C_DIM}Report saved: {report_path}{C_RESET}\n")


def show_scoreboard():
    """Show a scoreboard built from the saved reports."""
    report_dir = Path(__file__).parent / "reports"
    if not report_dir.exists():
        print(f"  {C_YELLOW}No report yet. Run an attack with --auto first.{C_RESET}")
        return

    reports = sorted(report_dir.glob("report_*.json"), reverse=True)
    if not reports:
        print(f"  {C_YELLOW}No reports yet.{C_RESET}")
        return

    print(f"\n{C_BOLD}  SCOREBOARD{C_RESET}")
    print(f"  {'─' * 55}")
    print(f"  {'Date':<20} {'Difficulty':<10} {'Score':<8} {'Success':<12}")
    print(f"  {'─' * 55}")

    for rpath in reports[:10]:
        with open(rpath, encoding="utf-8") as f:
            data = json.load(f)
        ts = data.get("timestamp", "?")
        date_str = f"{ts[:4]}-{ts[4:6]}-{ts[6:8]} {ts[9:11]}:{ts[11:13]}"
        diff = data.get("difficulty", "?")
        score = data.get("total_score", 0)
        success = data.get("total_success", 0)
        total = data.get("total_attacks", 0)
        print(f"  {date_str:<20} {diff:<10} {score:<8} {success}/{total}")

    print(f"  {'─' * 55}\n")


def build_parser() -> argparse.ArgumentParser:
    from targets import PROVIDERS

    parser = argparse.ArgumentParser(
        description="VulnLLM -- OWASP LLM Top 10 attack & defense lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--challenge", "-c", type=int, help="Challenge number (1-10)")
    parser.add_argument("--auto", "-a", action="store_true", help="Automated attack mode")
    parser.add_argument("--all", action="store_true", help="Run every challenge")
    parser.add_argument("--difficulty", "-d", choices=["easy", "medium", "hard", "expert"],
                        default="easy", help="Difficulty level (default: easy)")
    parser.add_argument("--provider", choices=PROVIDERS,
                        help="Play against a real model through this provider (default: the mock backend)")
    parser.add_argument("--model", "-m", type=str, default=None, help="Model name (no default)")
    parser.add_argument("--base-url", help="Endpoint base URL (openai-compatible)")
    parser.add_argument("--api-key-env", metavar="VAR", help="Environment variable holding the API key")
    parser.add_argument("--temperature", type=float, help="Sampling temperature (default: provider's own)")
    parser.add_argument("--ollama", "-o", action="store_true", help=argparse.SUPPRESS)  # deprecated
    parser.add_argument("--tier", "-t", help=argparse.SUPPRESS)  # removed: it named models
    parser.add_argument("--scoreboard", "-s", action="store_true", help="Scoreboard")
    return parser


def target_from_args(args: argparse.Namespace, env=None):
    """(target or None for the mock backend, deprecation warnings)."""
    from targets import build_target

    warnings: list[str] = []
    provider = args.provider
    if provider is None and args.ollama:
        if not args.model:
            raise ValueError("--ollama needs --model <local-model>; better: --provider ollama --model <m>")
        provider = "ollama"
        warnings.append(f"--ollama is deprecated; use --provider ollama --model {args.model}")
    if provider is None:
        return None, warnings
    target = build_target(provider, args.model or "", base_url=args.base_url, api_key_env=args.api_key_env,
                          env=env, temperature=args.temperature)
    return target, warnings


def main():
    make_output_safe()
    parser = build_parser()
    args = parser.parse_args()
    if args.tier:
        # The tiers named three 2024 models (dolphin-mistral, qwen2.5:3b,
        # llama3.2:3b) and claimed success rates nothing measured.
        print("[ERROR] --tier was removed: pass --provider <p> --model <m> for the model you want to test",
              file=sys.stderr)
        sys.exit(2)
    difficulty = DIFFICULTY_MAP[args.difficulty]

    try:
        target, warnings = target_from_args(args)
    except ValueError as e:
        print(f"[ERROR] {e}", file=sys.stderr)
        sys.exit(2)
    for w in warnings:
        print(f"[DEPRECATED] {w}", file=sys.stderr)
    if target is not None:
        print(f"\n  {C_MAGENTA}Real model: {getattr(target, 'model', '?')} ({type(target).__name__}){C_RESET}\n")

    if args.scoreboard:
        show_scoreboard()
        return

    if args.all and args.auto:
        run_all_auto(difficulty, target=target)
        return

    if args.challenge:
        if not 1 <= args.challenge <= 10:
            print(f"{C_RED}Invalid challenge: {args.challenge}. Choose between 1 and 10.{C_RESET}")
            sys.exit(1)

        ch_class = ALL_CHALLENGES[args.challenge - 1]
        challenge = ch_class(difficulty=difficulty, target=target)

        if args.auto:
            run_auto(challenge)
        else:
            run_interactive(challenge)
        return

    print_menu()


if __name__ == "__main__":
    main()
