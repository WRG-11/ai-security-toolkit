#!/usr/bin/env python3
"""
VulnLLM — Zafiyetli LLM Lab Ortami
OWASP LLM Top 10 saldiri & savunma pratigi.

Kullanim:
    python vulnllm.py                          # Ana menu
    python vulnllm.py --challenge 1            # Challenge 1 interaktif
    python vulnllm.py --challenge 1 --auto     # Challenge 1 otomatik saldiri
    python vulnllm.py --all --auto             # Tum challenge'lar otomatik
    python vulnllm.py --challenge 1 -d medium  # Orta zorluk
    python vulnllm.py --scoreboard             # Skor tablosu
"""

import sys
import json
import argparse
from pathlib import Path
from datetime import datetime

# Proje rootunu path'e ekle
sys.path.insert(0, str(Path(__file__).parent))

from config import (
    Difficulty, DIFFICULTY_MAP, C_RESET, C_BOLD, C_DIM, C_RED, C_GREEN,
    C_YELLOW, C_BLUE, C_MAGENTA, C_CYAN
)
from challenges import ALL_CHALLENGES


BANNER = f"""
{C_MAGENTA}{C_BOLD}
 ██╗   ██╗██╗   ██╗██╗     ███╗   ██╗██╗     ██╗     ███╗   ███╗
 ██║   ██║██║   ██║██║     ████╗  ██║██║     ██║     ████╗ ████║
 ██║   ██║██║   ██║██║     ██╔██╗ ██║██║     ██║     ██╔████╔██║
 ╚██╗ ██╔╝██║   ██║██║     ██║╚██╗██║██║     ██║     ██║╚██╔╝██║
  ╚████╔╝ ╚██████╔╝███████╗██║ ╚████║███████╗███████╗██║ ╚═╝ ██║
   ╚═══╝   ╚═════╝ ╚══════╝╚═╝  ╚═══╝╚══════╝╚══════╝╚═╝     ╚═╝
{C_RESET}
{C_BOLD}  OWASP LLM Top 10 — Saldiri & Savunma Lab Ortami{C_RESET}
{C_DIM}  v0.2 | Mock + Ollama | 10 Challenge | 194 Saldiri | 3 Tier{C_RESET}
"""


def print_menu():
    """Ana menu."""
    print(BANNER)
    print(f"  {C_BOLD}CHALLENGE'LAR:{C_RESET}\n")

    for ch_class in ALL_CHALLENGES:
        ch = ch_class()
        print(f"    {C_CYAN}{ch.id:2d}.{C_RESET} [{ch.owasp_id}] {ch.name}")
        print(f"        {C_DIM}{ch.description}{C_RESET}")

    print(f"\n  {C_BOLD}ZORLUK SEVIYELERI:{C_RESET}")
    print(f"    {C_GREEN}easy{C_RESET}   — Savunma yok, temel teknikleri ogren")
    print(f"    {C_YELLOW}medium{C_RESET} — Basit filtreler, bypass tekniklerini ogren")
    print(f"    {C_RED}hard{C_RESET}   — Katmanli savunma, gercek dunya senaryosu")

    print(f"\n  {C_BOLD}MODEL TIER'LARI (--ollama --tier <T>):{C_RESET}")
    print(f"    {C_GREEN}t1{C_RESET}  — Uncensored (dolphin-mistral) — guvenlik yok, saldiri ogren")
    print(f"    {C_YELLOW}t2{C_RESET}  — Zayif RLHF (qwen2.5:3b)     — bypass tekniklerini ogren")
    print(f"    {C_RED}t3{C_RESET}  — Guclu (llama3.2:3b)          — gelismis teknikler")

    print(f"\n  {C_BOLD}KOMUTLAR:{C_RESET}")
    print(f"    {C_DIM}Mock (varsayilan):{C_RESET}")
    print(f"    python vulnllm.py --challenge <N>              Interaktif mod")
    print(f"    python vulnllm.py --challenge <N> --auto       Otomatik saldiri")
    print(f"    python vulnllm.py --all --auto -d medium       Tumu medium modda")
    print(f"    {C_DIM}Ollama (gercek LLM):{C_RESET}")
    print(f"    python vulnllm.py -c 1 --ollama --tier t1      T1 ile CH01 interaktif")
    print(f"    python vulnllm.py -c 1 --ollama --tier t2 -a   T2 ile CH01 otomatik")
    print(f"    python vulnllm.py --all -o -t t1 -a            Tum challenge T1 otomatik")
    print(f"    {C_DIM}Diger:{C_RESET}")
    print(f"    python vulnllm.py --scoreboard                 Skor tablosu")
    print()


def run_interactive(challenge):
    """Interaktif chat modu."""
    challenge.print_banner()

    print(f"\n  {C_CYAN}Interaktif Mod{C_RESET} — Chatbot'a saldiri deneyin.")
    print(f"  {C_DIM}Komutlar: 'quit' (cik), 'attacks' (hazir saldirilari goster),")
    print(f"           'info' (savunma bilgisi), 'score' (skor){C_RESET}\n")

    while True:
        try:
            user_input = input(f"  {C_GREEN}saldiri>{C_RESET} ")
        except (KeyboardInterrupt, EOFError):
            print("\n  Cikis.")
            break

        if not user_input.strip():
            continue

        cmd = user_input.strip().lower()

        if cmd in ("quit", "exit", "q", "cik"):
            break

        elif cmd == "attacks":
            print(f"\n  {C_BOLD}Hazir Saldiri Teknikleri:{C_RESET}")
            for i, tech in enumerate(challenge.get_attack_techniques(), 1):
                sev_color = C_RED if tech["severity"] == "CRITICAL" else C_YELLOW if tech["severity"] == "HIGH" else C_CYAN
                print(f"    {i}. {sev_color}[{tech['severity']}]{C_RESET} {tech['name']}")
                print(f"       {C_DIM}Payload: {tech['payload'][:70]}{C_RESET}")
                print(f"       {C_DIM}Aciklama: {tech['explanation']}{C_RESET}")
            print(f"\n  {C_DIM}Kullanmak icin numarayi yazin (orn: '1') veya kendi payload'unuzu girin.{C_RESET}\n")
            continue

        elif cmd == "info":
            print(f"\n  {C_BOLD}Savunma Bilgisi:{C_RESET} {challenge.get_defense_info()}")
            print(f"  {C_BOLD}Hedef:{C_RESET} {challenge.objective}\n")
            continue

        elif cmd == "score":
            print(f"\n  {C_BOLD}Skor:{C_RESET} {challenge.state.score} puan")
            print(f"  {C_BOLD}Basarili Saldirilar:{C_RESET} {len(challenge.state.successful_attacks)}")
            print(f"  {C_BOLD}Bloklanan:{C_RESET} {len(challenge.state.blocked_attacks)}\n")
            continue

        # Numara ile hazir saldiri secimi
        if cmd.isdigit():
            idx = int(cmd) - 1
            techniques = challenge.get_attack_techniques()
            if 0 <= idx < len(techniques):
                user_input = techniques[idx]["payload"]
                print(f"  {C_DIM}Payload: {user_input}{C_RESET}")
            else:
                print(f"  {C_RED}Gecersiz numara. 1-{len(techniques)} arasi secin.{C_RESET}")
                continue

        # Chat
        response = challenge.chat(user_input)
        success = challenge.check_success(response.content)

        if response.blocked:
            print(f"\n  {C_RED}[BLOKLANDI]{C_RESET} {response.content}\n")
        elif success:
            print(f"\n  {C_GREEN}[BASARILI!]{C_RESET} {response.content}\n")
            print(f"  {C_GREEN}+{challenge.state.score} puan kazanildi!{C_RESET}\n")
        else:
            print(f"\n  {C_YELLOW}[YANITDI]{C_RESET} {response.content}\n")


def run_auto(challenge):
    """Otomatik saldiri modu."""
    challenge.print_banner()

    print(f"\n  {C_MAGENTA}Otomatik Saldiri Modu{C_RESET} — Tum teknikler deneniyor...\n")

    results = challenge.run_all_attacks()

    for result in results:
        challenge.print_attack_result(result)

    challenge.print_summary(results)
    return challenge.get_report(results)


def run_all_auto(difficulty: Difficulty, use_ollama: bool = False, model_tier=None, model_override=None):
    """Tum challenge'lari otomatik calistir."""
    print(BANNER)
    backend_label = f" | Ollama {model_tier.value.upper()}" if use_ollama else " | Mock"
    print(f"  {C_MAGENTA}{C_BOLD}TUM CHALLENGE'LAR — {difficulty.name} MOD{backend_label}{C_RESET}\n")

    all_reports = []
    total_score = 0
    total_success = 0
    total_attacks = 0

    for ch_class in ALL_CHALLENGES:
        challenge = ch_class(
            difficulty=difficulty,
            use_ollama=use_ollama,
            model_tier=model_tier if use_ollama else None,
            model_override=model_override,
        )
        report = run_auto(challenge)
        all_reports.append(report)
        total_score += report["score"]
        total_success += report["successful"]
        total_attacks += report["total_attacks"]
        print()

    # Genel ozet
    print(f"\n{'=' * 65}")
    print(f"{C_BOLD}{C_MAGENTA}  GENEL SONUC TABLOSU{C_RESET}")
    print(f"{'=' * 65}")
    print(f"  Zorluk:             {difficulty.name}")
    print(f"  Toplam Challenge:   {len(ALL_CHALLENGES)}")
    print(f"  Toplam Saldiri:     {total_attacks}")
    print(f"  {C_GREEN}Basarili:           {total_success}/{total_attacks}{C_RESET}")
    print(f"  {C_BOLD}Toplam Skor:        {total_score}{C_RESET}")

    print(f"\n  {C_BOLD}Challenge Bazli:{C_RESET}")
    for r in all_reports:
        status = f"{C_GREEN}GECTI{C_RESET}" if r["successful"] > 0 else f"{C_RED}KALDI{C_RESET}"
        print(f"    #{r['challenge_id']:2d} [{r['owasp_id']}] {r['challenge_name']:<35} "
              f"{r['successful']}/{r['total_attacks']} saldiri  {status}")

    print(f"\n{'=' * 65}")

    # Raporu kaydet
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
    print(f"\n  {C_DIM}Rapor kaydedildi: {report_path}{C_RESET}\n")


def show_scoreboard():
    """Kayitli raporlardan skor tablosu goster."""
    report_dir = Path(__file__).parent / "reports"
    if not report_dir.exists():
        print(f"  {C_YELLOW}Henuz rapor yok. Once --auto ile saldiri calistirin.{C_RESET}")
        return

    reports = sorted(report_dir.glob("report_*.json"), reverse=True)
    if not reports:
        print(f"  {C_YELLOW}Henuz rapor yok.{C_RESET}")
        return

    print(f"\n{C_BOLD}  SKOR TABLOSU{C_RESET}")
    print(f"  {'─' * 55}")
    print(f"  {'Tarih':<20} {'Zorluk':<10} {'Skor':<8} {'Basari':<12}")
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


def main():
    parser = argparse.ArgumentParser(
        description="VulnLLM — OWASP LLM Top 10 Saldiri & Savunma Lab",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--challenge", "-c", type=int, help="Challenge numarasi (1-10)")
    parser.add_argument("--auto", "-a", action="store_true", help="Otomatik saldiri modu")
    parser.add_argument("--all", action="store_true", help="Tum challenge'lari calistir")
    parser.add_argument("--difficulty", "-d", choices=["easy", "medium", "hard", "expert"],
                        default="easy", help="Zorluk seviyesi (default: easy)")
    parser.add_argument("--ollama", "-o", action="store_true",
                        help="Ollama backend kullan (gercek LLM)")
    parser.add_argument("--tier", "-t", choices=["t1", "t2", "t3"], default="t1",
                        help="Model tier: t1=uncensored, t2=weak, t3=strong (default: t1)")
    parser.add_argument("--model", "-m", type=str, default=None,
                        help="Ollama model adi (tier'i override eder, orn: deepseek-r1:8b)")
    parser.add_argument("--scoreboard", "-s", action="store_true", help="Skor tablosu")

    args = parser.parse_args()
    difficulty = DIFFICULTY_MAP[args.difficulty]

    # Ollama tier mapping
    from backend.ollama import ModelTier, OllamaBackend, TIER_MODELS
    tier_map = {"t1": ModelTier.T1_UNCENSORED, "t2": ModelTier.T2_WEAK, "t3": ModelTier.T3_STRONG}
    model_tier = tier_map[args.tier]

    # Ollama kontrolleri
    model_override = args.model
    if args.ollama:
        test_backend = OllamaBackend(tier=model_tier, model_override=model_override)
        if not test_backend.is_available():
            print(f"{C_RED}Ollama sunucusu calismiyoir! 'ollama serve' calistirin.{C_RESET}")
            sys.exit(1)
        if not test_backend.model_exists():
            model_name = model_override or TIER_MODELS[model_tier]["model"]
            print(f"{C_RED}Model bulunamadi: {model_name}")
            print(f"Yuklemek icin: ollama pull {model_name}{C_RESET}")
            sys.exit(1)
        if model_override:
            print(f"\n  {C_MAGENTA}Ollama Backend Aktif: {model_override} (custom){C_RESET}\n")
        else:
            tier_info = TIER_MODELS[model_tier]
            print(f"\n  {C_MAGENTA}Ollama Backend Aktif: {tier_info['label']}{C_RESET}")
            print(f"  {C_DIM}{tier_info['description']}{C_RESET}\n")

    if args.scoreboard:
        show_scoreboard()
        return

    if args.all and args.auto:
        run_all_auto(difficulty, use_ollama=args.ollama, model_tier=model_tier,
                     model_override=model_override)
        return

    if args.challenge:
        if not 1 <= args.challenge <= 10:
            print(f"{C_RED}Gecersiz challenge: {args.challenge}. 1-10 arasi secin.{C_RESET}")
            sys.exit(1)

        ch_class = ALL_CHALLENGES[args.challenge - 1]
        challenge = ch_class(
            difficulty=difficulty,
            use_ollama=args.ollama,
            model_tier=model_tier if args.ollama else None,
            model_override=model_override,
        )

        if args.auto:
            run_auto(challenge)
        else:
            run_interactive(challenge)
        return

    print_menu()


if __name__ == "__main__":
    main()
