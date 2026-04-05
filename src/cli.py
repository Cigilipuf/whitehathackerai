"""
WhiteHatHacker AI — CLI Arayüzü

Rich/Typer tabanlı komut satırı arayüzü.
Tarama başlatma, mod değiştirme, durum sorgulama, araç yönetimi.
"""

from __future__ import annotations

import asyncio
import time
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

from src.utils.constants import OperationMode


app = typer.Typer(
    name="whai",
    help="WhiteHatHacker AI — Autonomous Bug Bounty Hunter Bot",
    rich_markup_mode="rich",
)
console = Console()


# ============================================================
# Banner
# ============================================================

BANNER = """
[bold cyan]
 ██╗    ██╗██╗  ██╗ █████╗ ██╗
 ██║    ██║██║  ██║██╔══██╗██║
 ██║ █╗ ██║███████║███████║██║
 ██║███╗██║██╔══██║██╔══██║██║
 ╚███╔███╔╝██║  ██║██║  ██║██║
  ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝
[/bold cyan]
[bold white]WhiteHatHacker AI v3.5[/bold white]
[dim]Autonomous Bug Bounty Hunter Bot[/dim]
[dim]Unified Brain: BaronLLM v2 (Think / NoThink)[/dim]
"""


def show_banner() -> None:
    console.print(BANNER)


# ============================================================
# Komutlar
# ============================================================

@app.command()
def scan(
    target: str = typer.Argument(..., help="Hedef domain, URL veya IP"),
    scope_file: Optional[str] = typer.Option(None, "--scope", "-s", help="Scope dosyası (YAML)"),
    mode: str = typer.Option("semi-autonomous", "--mode", "-m", help="Çalışma modu: autonomous | semi-autonomous"),
    profile: str = typer.Option("balanced", "--profile", "-p", help="Tarama profili: stealth | balanced | aggressive"),
    pipeline: str = typer.Option("full", "--pipeline", help="Pipeline tipi: full | web | api | network | quick_recon | agentic"),
    config: str = typer.Option("config/settings.yaml", "--config", "-c", help="Konfigürasyon dosyası"),
    output: str = typer.Option("output/reports", "--output", "-o", help="Çıktı dizini"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Ayrıntılı çıktı modu — tüm logları terminale göster"),
    verbose_live: bool = typer.Option(False, "--verbose-live", "-V", help="Rich Live ayrıntılı panel (tam dashboard)"),
    no_brain: bool = typer.Option(False, "--no-brain", help="LLM olmadan tarama yap (ÖNERİLMEZ — kalite düşer)"),
    auth_cookie: Optional[str] = typer.Option(None, "--auth-cookie", help="Auth cookie (ör: 'session=abc123; token=xyz')"),
    auth_header: Optional[list[str]] = typer.Option(None, "--auth-header", help="Auth header (tekrar edilebilir, ör: --auth-header 'Authorization: Bearer xxx')"),
    auth_file: Optional[str] = typer.Option(None, "--auth-file", help="Auth JSON dosyası (keys: cookies, headers)"),
    dry_run: bool = typer.Option(False, "--dry-run", help="Pipeline önizlemesi — gerçek istek göndermeden araç planını göster"),
    incremental: bool = typer.Option(False, "--incremental", help="Sadece yeni/değişen asset'leri tara (önceki scan ile karşılaştırır)"),
    resume_latest: bool = typer.Option(True, "--resume-latest/--no-resume-latest", help="Aynı hedef için kesilmiş son oturumu otomatik tespit et ve devam ettir"),
    max_iterations: Optional[int] = typer.Option(None, "--max-iterations", help="Agentic döngü max iterasyon (varsayılan: profil bazlı)"),
    time_budget: Optional[float] = typer.Option(None, "--time-budget", help="Zaman bütçesi saat cinsinden (varsayılan: profil bazlı)"),
) -> None:
    """Hedef üzerinde tam tarama başlat."""
    show_banner()

    # ── Dry-run mode: show plan and exit ──
    if dry_run:
        from src.workflow.pipelines.dry_run import dry_run_plan, format_dry_run
        scope_data = None
        if scope_file:
            import yaml
            try:
                with open(scope_file, encoding="utf-8") as f:
                    scope_data = yaml.safe_load(f)
            except Exception:
                pass
        plan = dry_run_plan(target, profile, scope_data)
        console.print(format_dry_run(plan))
        raise typer.Exit(code=0)

    # Validate mode and profile values early
    _valid_modes = ("autonomous", "semi-autonomous")
    _valid_profiles = ("stealth", "balanced", "aggressive", "custom")
    _valid_pipelines = ("full", "web", "api", "network", "quick_recon", "agentic")
    if mode not in _valid_modes:
        console.print(f"[bold red]Geçersiz mod:[/bold red] '{mode}'")
        console.print(f"Geçerli modlar: {', '.join(_valid_modes)}")
        raise typer.Exit(code=1)
    if profile not in _valid_profiles:
        console.print(f"[bold red]Geçersiz profil:[/bold red] '{profile}'")
        console.print(f"Geçerli profiller: {', '.join(_valid_profiles)}")
        raise typer.Exit(code=1)
    if pipeline not in _valid_pipelines:
        console.print(f"[bold red]Geçersiz pipeline:[/bold red] '{pipeline}'")
        console.print(f"Geçerli pipeline'lar: {', '.join(_valid_pipelines)}")
        raise typer.Exit(code=1)

    # ── Auto-resume interrupted sessions for the same target ──
    if resume_latest and not dry_run:
        from src.workflow.session_manager import SessionManager

        sm = SessionManager(output_dir="output")
        matching_incomplete = sm.find_incomplete_sessions(target=target)
        if matching_incomplete:
            latest = matching_incomplete[0]
            should_resume = mode == "autonomous"
            if not should_resume:
                should_resume = typer.confirm(
                    (
                        f"'{target}' için yarım kalmış bir oturum bulundu "
                        f"({latest.metadata.session_id}, stage={latest.metadata.current_stage or 'unknown'}). "
                        "Devam edilsin mi?"
                    ),
                    default=True,
                )
            if should_resume:
                console.print(Panel(
                    f"[bold]Session:[/bold] {latest.metadata.session_id}\n"
                    f"[bold]Target:[/bold] {latest.metadata.target}\n"
                    f"[bold]Status:[/bold] {latest.metadata.status}\n"
                    f"[bold]Current Stage:[/bold] {latest.metadata.current_stage or 'unknown'}\n"
                    f"[bold]Completed Stages:[/bold] {len(latest.metadata.completed_stages)}\n"
                    f"[bold]Findings:[/bold] {latest.metadata.findings_total}",
                    title="[bold green]Otomatik Resume[/bold green]",
                    border_style="green",
                ))
                from src.main import resume_scan

                asyncio.run(resume_scan(
                    session_id=latest.metadata.session_id,
                    config_path=config,
                    allow_no_brain=no_brain,
                ))
                return

    console.print(Panel(
        f"[bold]Hedef:[/bold] {target}\n"
        f"[bold]Mod:[/bold] {mode}\n"
        f"[bold]Profil:[/bold] {profile}\n"
        f"[bold]Pipeline:[/bold] {pipeline}\n"
        f"[bold]Scope:[/bold] {scope_file or 'Belirtilmedi'}\n"
        f"[bold]Çıktı:[/bold] {output}\n"
        f"[bold]Brain:[/bold] {'DISABLED (--no-brain)' if no_brain else 'Enabled'}\n"
        f"[bold]Verbose:[/bold] {'Live Dashboard' if verbose_live else 'Renkli Log' if verbose else 'Normal'}",
        title="[bold green]Tarama Başlatılıyor[/bold green]",
        border_style="green",
    ))

    if no_brain:
        console.print(Panel(
            "[bold red]UYARI:[/bold red] --no-brain bayrağı aktif!\n"
            "LLM beyin DEVRE DIŞI — FP eleme, derin analiz ve rapor kalitesi\n"
            "ciddi ölçüde düşecektir. Bu modu sadece test için kullanın.",
            title="[bold red]⚠ AI Brain Devre Dışı[/bold red]",
            border_style="red",
        ))

    # ── Build auth_headers from CLI flags ──
    scan_auth_headers: dict[str, str] = {}
    if auth_file:
        import json as _json
        try:
            with open(auth_file, encoding="utf-8") as f:
                auth_data = _json.load(f)
            if isinstance(auth_data.get("headers"), dict):
                scan_auth_headers.update(auth_data["headers"])
            if isinstance(auth_data.get("cookies"), str):
                scan_auth_headers["Cookie"] = auth_data["cookies"]
            elif isinstance(auth_data.get("cookies"), dict):
                scan_auth_headers["Cookie"] = "; ".join(
                    f"{k}={v}" for k, v in auth_data["cookies"].items()
                )
        except (FileNotFoundError, _json.JSONDecodeError, KeyError) as e:
            console.print(f"[bold red]Auth dosyası okunamadı:[/bold red] {e}")
            raise typer.Exit(code=1)
    if auth_header:
        for h in auth_header:
            if ":" in h:
                key, _, val = h.partition(":")
                scan_auth_headers[key.strip()] = val.strip()
    if auth_cookie:
        existing = scan_auth_headers.get("Cookie", "")
        scan_auth_headers["Cookie"] = f"{existing}; {auth_cookie}".lstrip("; ") if existing else auth_cookie

    if scan_auth_headers:
        console.print(Panel(
            f"[bold green]Authenticated scanning aktif[/bold green]\n"
            f"Header sayısı: {len(scan_auth_headers)}\n"
            f"Keys: {', '.join(scan_auth_headers.keys())}",
            title="[bold cyan]🔐 Auth Context[/bold cyan]",
            border_style="cyan",
        ))

    # Verbose mod ayarları
    verbose_display = None
    verbose_sink_id = None

    if verbose_live:
        # Rich Live dashboard — tam panel modda
        from src.utils.verbose_display import VerboseDisplay, get_verbose_state
        state = get_verbose_state()
        state.update(target=target, mode=mode)
        verbose_display = VerboseDisplay(console)
        verbose_display.start()
    elif verbose:
        # Basit renkli log modu — her şeyi terminale bas
        from src.utils.verbose_display import setup_simple_verbose_sink, get_verbose_state
        state = get_verbose_state()
        state.update(target=target, mode=mode)
        verbose_sink_id = setup_simple_verbose_sink()

    # Scope dosyasını yükle
    scope = None
    if scope_file:
        import yaml
        try:
            with open(scope_file, encoding="utf-8") as f:
                scope = yaml.safe_load(f)
        except FileNotFoundError:
            console.print(f"[bold red]Scope dosyası bulunamadı:[/bold red] {scope_file}")
            raise typer.Exit(code=1)
        except yaml.YAMLError as e:
            console.print(f"[bold red]Scope dosyası geçersiz YAML:[/bold red] {e}")
            raise typer.Exit(code=1)

    try:
        # Async taramayı başlat
        from src.main import run_scan
        asyncio.run(run_scan(
            target=target,
            scope=scope,
            config_path=config,
            mode_override=mode,
            profile_override=profile,
            allow_no_brain=no_brain,
            auth_headers=scan_auth_headers or None,
            incremental=incremental,
            pipeline_type=pipeline,
            max_iterations=max_iterations,
            time_budget_hours=time_budget,
        ))
    finally:
        # Verbose temizlik
        if verbose_display:
            verbose_display.stop()
        if verbose_sink_id is not None:
            from loguru import logger as _logger
            try:
                _logger.remove(verbose_sink_id)
            except ValueError:
                pass


@app.command()
def resume(
    session_id: Optional[str] = typer.Argument(None, help="Session ID to resume (omit to auto-detect latest incomplete)"),
    config: str = typer.Option("config/settings.yaml", "--config", "-c", help="Konfigürasyon dosyası"),
    no_brain: bool = typer.Option(False, "--no-brain", help="LLM olmadan tarama yap"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Ayrıntılı çıktı modu"),
) -> None:
    """Resume an interrupted/crashed scan from its last checkpoint."""
    show_banner()

    from src.workflow.session_manager import SessionManager

    sm = SessionManager(output_dir="output")

    # If no session_id, find latest incomplete session
    if not session_id:
        incomplete = sm.find_incomplete_sessions()
        if not incomplete:
            console.print("[yellow]No incomplete sessions found.[/yellow]")
            raise typer.Exit(code=0)
        # Show list and pick latest
        table = Table(title="Incomplete Sessions", show_lines=True)
        table.add_column("Session ID", style="cyan")
        table.add_column("Target", style="white")
        table.add_column("Status", style="yellow")
        table.add_column("Stages Done", style="green")
        table.add_column("Findings", style="magenta")
        for s in incomplete:
            table.add_row(
                s.metadata.session_id,
                s.metadata.target,
                str(s.metadata.status),
                str(len(s.metadata.completed_stages)),
                str(s.metadata.findings_total),
            )
        console.print(table)
        session_id = incomplete[0].metadata.session_id
        console.print(f"\n[bold]Resuming latest:[/bold] {session_id}")

    # Load session
    session = sm.load_session(session_id)
    if not session:
        console.print(f"[bold red]Session not found:[/bold red] {session_id}")
        raise typer.Exit(code=1)

    console.print(Panel(
        f"[bold]Session:[/bold] {session_id}\n"
        f"[bold]Target:[/bold] {session.metadata.target}\n"
        f"[bold]Status:[/bold] {session.metadata.status}\n"
        f"[bold]Completed Stages:[/bold] {', '.join(session.metadata.completed_stages) or 'None'}\n"
        f"[bold]Findings:[/bold] {session.metadata.findings_total}\n"
        f"[bold]Brain:[/bold] {'DISABLED' if no_brain else 'Enabled'}",
        title="[bold green]Resuming Scan[/bold green]",
        border_style="green",
    ))

    verbose_sink_id = None
    if verbose:
        from src.utils.verbose_display import setup_simple_verbose_sink, get_verbose_state
        state = get_verbose_state()
        state.update(target=session.metadata.target, mode="resume")
        verbose_sink_id = setup_simple_verbose_sink()

    try:
        from src.main import resume_scan
        asyncio.run(resume_scan(
            session_id=session_id,
            config_path=config,
            allow_no_brain=no_brain,
        ))
    finally:
        if verbose_sink_id is not None:
            from loguru import logger as _logger
            try:
                _logger.remove(verbose_sink_id)
            except ValueError:
                pass


@app.command()
def tools(
    check: bool = typer.Option(False, "--check", help="Araç erişilebilirlik kontrolü"),
    category: Optional[str] = typer.Option(None, "--category", "-c", help="Kategori filtresi"),
) -> None:
    """Kayıtlı güvenlik araçlarını listele."""
    show_banner()

    from src.tools.register_tools import register_all_tools
    from src.tools.registry import tool_registry

    register_all_tools(tool_registry)

    table = Table(title="Güvenlik Araçları", show_lines=True)
    table.add_column("Araç", style="cyan", no_wrap=True)
    table.add_column("Kategori", style="blue")
    table.add_column("Risk", style="yellow")
    table.add_column("Durum", style="green")

    tools_list = tool_registry.list_tools()

    if not tools_list:
        console.print("[yellow]Henüz kayıtlı araç yok.[/yellow]")
        console.print("Araçları kaydetmek için tool wrapper'ları implement edin.")
        return

    for tool_info in tools_list:
        if category and tool_info["category"] != category:
            continue

        status = "[green]✓ Kurulu[/green]" if tool_info["available"] else "[red]✗ Eksik[/red]"
        table.add_row(
            tool_info["name"],
            str(tool_info["category"]),
            str(tool_info["risk_level"]),
            status,
        )

    console.print(table)

    if check:
        health = tool_registry.health_check()
        console.print(Panel(
            f"[bold]Toplam:[/bold] {health['total_registered']}\n"
            f"[green]Kurulu:[/green] {health['available']}\n"
            f"[red]Eksik:[/red] {health['unavailable']}\n"
            f"[bold]Oran:[/bold] %{health['availability_rate']}",
            title="[bold]Araç Sağlık Kontrolü[/bold]",
        ))


@app.command()
def status() -> None:
    """Bot durumunu göster."""
    show_banner()

    console.print(Panel(
        "[bold green]WhiteHatHacker AI v3.5[/bold green]\n\n"
        "[bold]Beyin Modelleri:[/bold]\n"
        "  Primary:   BaronLLM v2 (Think Mode)\n"
        "  Secondary: BaronLLM v2 (NoThink Mode)\n\n"
        "[bold]Durum:[/bold] Hazır\n"
        "[bold]Mod:[/bold] Hibrit (semi-autonomous)\n",
        title="[bold cyan]Sistem Durumu[/bold cyan]",
        border_style="cyan",
    ))


@app.command(name="switch-mode")
def switch_mode(
    mode: str = typer.Argument(..., help="Yeni mod: autonomous | semi-autonomous"),
) -> None:
    """Çalışma modunu değiştir."""
    try:
        new_mode = OperationMode(mode)
        # Persist change to settings.yaml
        from pathlib import Path as _Path
        _settings_path = _Path("config/settings.yaml")
        if _settings_path.exists():
            import yaml
            with open(_settings_path, "r") as _f:
                _cfg = yaml.safe_load(_f) or {}
            _cfg.setdefault("general", {})["mode"] = new_mode.value
            with open(_settings_path, "w") as _f:
                yaml.dump(_cfg, _f, default_flow_style=False, allow_unicode=True)
        console.print(f"[bold green]Mod değiştirildi:[/bold green] {new_mode}")
    except ValueError:
        console.print(f"[bold red]Geçersiz mod:[/bold red] {mode}")
        console.print("Geçerli modlar: autonomous, semi-autonomous")


@app.command()
def health() -> None:
    """Sistem sağlık kontrolü çalıştır."""
    show_banner()

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Sistem kontrol ediliyor...", total=None)

        # Tool registry kontrolü
        from src.tools.register_tools import register_all_tools
        from src.tools.registry import tool_registry
        register_all_tools(tool_registry)
        health_data = tool_registry.health_check()

        progress.update(task, description="Kontrol tamamlandı")

    console.print(Panel(
        f"[bold]Araçlar:[/bold] {health_data['available']}/{health_data['total_registered']} kurulu\n"
        f"[bold]Oran:[/bold] %{health_data['availability_rate']}",
        title="[bold]Sağlık Raporu[/bold]",
    ))

    if health_data["unavailable_tools"]:
        console.print("\n[bold yellow]Eksik Araçlar:[/bold yellow]")
        for tool_name in health_data["unavailable_tools"]:
            console.print(f"  [red]✗[/red] {tool_name}")


@app.command()
def version() -> None:
    """Versiyon bilgisi göster."""
    console.print("[bold]WhiteHatHacker AI[/bold] v3.5")


@app.command()
def watch(
    session_id: Optional[str] = typer.Argument(None, help="İzlenecek session ID (boşsa en güncel uygun oturum seçilir)"),
    target: Optional[str] = typer.Option(None, "--target", "-t", help="Hedefe göre oturum seç"),
    every_minutes: int = typer.Option(20, "--every-minutes", min=1, help="Kontrol aralığı (dakika)"),
    iterations: int = typer.Option(1, "--iterations", min=1, help="Kaç gözlem yapılacağı"),
    write_notes: bool = typer.Option(True, "--write-notes/--no-write-notes", help="Session altına markdown gözlem notu yaz"),
) -> None:
    """Scan oturumunu periyodik olarak izle ve operatör notu üret."""
    show_banner()

    from src.workflow.scan_monitor import ScanMonitor

    monitor = ScanMonitor()
    for index in range(iterations):
        observation = monitor.collect_observation(session_id=session_id, target=target)

        recommendations = "\n".join(f"  - {item}" for item in observation.recommendations)
        signals = "\n".join(f"  - {item}" for item in observation.latest_signals[:5])

        console.print(Panel(
            f"[bold]Session:[/bold] {observation.session_id}\n"
            f"[bold]Target:[/bold] {observation.target}\n"
            f"[bold]Status:[/bold] {observation.status}\n"
            f"[bold]Stage:[/bold] {observation.current_stage or 'unknown'}\n"
            f"[bold]Elapsed:[/bold] {observation.elapsed_seconds:.0f}s\n"
            f"[bold]Findings:[/bold] raw={observation.findings_total} verified={observation.findings_verified} fp={observation.findings_fp}\n"
            f"[bold]Signals:[/bold] warnings={observation.warning_count} errors={observation.error_count} timeouts={observation.timeout_count}\n\n"
            f"[bold]Recent Signals[/bold]\n{signals or '  - none'}\n\n"
            f"[bold]Recommendations[/bold]\n{recommendations}",
            title="[bold cyan]Scan Watch[/bold cyan]",
            border_style="cyan",
        ))

        if write_notes:
            note_path = monitor.write_observation_note(observation)
            console.print(f"[green]Observation note written:[/green] {note_path}")

        if index < iterations - 1 and observation.status not in {"completed", "failed", "aborted"}:
            console.print(f"[dim]Next check in {every_minutes} minute(s)...[/dim]")
            time.sleep(every_minutes * 60)


@app.command()
def diagnose(
    skip_tools: bool = typer.Option(False, "--skip-tools", help="Sistem araç kontrolünü atla"),
    skip_brain: bool = typer.Option(False, "--skip-brain", help="Brain bağlantı kontrolünü atla"),
) -> None:
    """Geliştirme tanılama raporu oluştur (import, config, sistem, brain)."""
    show_banner()

    from src.utils.dev_diagnostics import run_diagnostics_sync

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    ) as progress:
        task = progress.add_task("Tanılama çalıştırılıyor...", total=None)
        report = run_diagnostics_sync(
            check_tools=not skip_tools,
            check_brain=not skip_brain,
        )
        progress.update(task, description="Tanılama tamamlandı")

    console.print(report.to_text())

    total = len(report.results)
    ok = report.ok_count
    warn = report.warn_count
    fail = report.fail_count
    skip = report.skip_count
    style = "green" if fail == 0 else "red" if fail > 3 else "yellow"
    console.print(Panel(
        f"[bold]Toplam:[/bold] {total}  "
        f"[green]OK:[/green] {ok}  "
        f"[yellow]WARN:[/yellow] {warn}  "
        f"[red]FAIL:[/red] {fail}  "
        f"[dim]SKIP:[/dim] {skip}",
        title="[bold]Tanılama Özeti[/bold]",
        border_style=style,
    ))


@app.command()
def monitor(
    target: str = typer.Argument(..., help="Sürekli izlenecek hedef domain/URL"),
    scope_file: Optional[str] = typer.Option(None, "--scope", "-s", help="Scope dosyası (YAML)"),
    profile: str = typer.Option("balanced", "--profile", "-p", help="Tarama profili"),
    mode: str = typer.Option("autonomous", "--mode", "-m", help="Çalışma modu"),
    config: str = typer.Option("config/settings.yaml", "--config", "-c", help="Konfigürasyon dosyası"),
    output: str = typer.Option("output", "--output", "-o", help="Çıktı dizini"),
    interval: int = typer.Option(120, "--interval", help="Tarama aralığı (dakika)"),
    max_iterations: int = typer.Option(0, "--max-iterations", help="Maks iterasyon (0=sonsuz)"),
    no_brain: bool = typer.Option(False, "--no-brain", help="LLM olmadan tara"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Ayrıntılı çıktı"),
) -> None:
    """Hedefi sürekli izle — periyodik scan + diff + alert."""
    show_banner()

    console.print(Panel(
        f"[bold]Target:[/bold] {target}\n"
        f"[bold]Interval:[/bold] {interval} minutes\n"
        f"[bold]Max Iterations:[/bold] {max_iterations or 'infinite'}\n"
        f"[bold]Profile:[/bold] {profile}\n"
        f"[bold]Scope:[/bold] {scope_file or 'auto'}",
        title="[bold green]Continuous Monitor[/bold green]",
        border_style="green",
    ))

    from src.workflow.continuous_monitor import ContinuousMonitor

    cm = ContinuousMonitor(
        target=target,
        scope_file=scope_file,
        profile=profile,
        mode=mode,
        config_path=config,
        output_dir=output,
        verbose=verbose,
        no_brain=no_brain,
    )
    asyncio.run(cm.run(interval_minutes=interval, max_iterations=max_iterations))


@app.command()
def campaign(
    targets_file: str = typer.Argument(..., help="Hedef listesi dosyası (satır başına bir hedef)"),
    scope_dir: Optional[str] = typer.Option(None, "--scope-dir", "-s", help="Scope dosyaları dizini"),
    profile: str = typer.Option("balanced", "--profile", "-p", help="Tarama profili"),
    mode: str = typer.Option("autonomous", "--mode", "-m", help="Çalışma modu"),
    config: str = typer.Option("config/settings.yaml", "--config", "-c", help="Konfigürasyon dosyası"),
    output: str = typer.Option("output", "--output", "-o", help="Çıktı dizini"),
    no_brain: bool = typer.Option(False, "--no-brain", help="LLM olmadan tara"),
    incremental: bool = typer.Option(False, "--incremental", help="Sadece yeni asset'leri tara"),
) -> None:
    """Birden fazla hedefi sırayla tara — kampanya modu."""
    show_banner()

    from pathlib import Path
    from src.workflow.campaign_manager import CampaignManager

    tf = Path(targets_file)
    if not tf.exists():
        console.print(f"[bold red]Hedef dosyası bulunamadı:[/bold red] {targets_file}")
        raise typer.Exit(code=1)

    targets = [l.strip() for l in tf.read_text(encoding="utf-8").splitlines()
               if l.strip() and not l.strip().startswith("#")]
    if not targets:
        console.print("[bold red]Hedef dosyasında geçerli hedef bulunamadı.[/bold red]")
        raise typer.Exit(code=1)

    console.print(Panel(
        f"[bold]Targets:[/bold] {len(targets)}\n"
        f"[bold]Scope Dir:[/bold] {scope_dir or 'auto-match'}\n"
        f"[bold]Profile:[/bold] {profile}\n"
        f"[bold]Mode:[/bold] {mode}\n\n"
        + "\n".join(f"  • {t}" for t in targets[:10])
        + (f"\n  ... and {len(targets) - 10} more" if len(targets) > 10 else ""),
        title="[bold green]Campaign Mode[/bold green]",
        border_style="green",
    ))

    mgr = CampaignManager(
        targets=targets,
        scope_dir=scope_dir,
        profile=profile,
        mode=mode,
        config_path=config,
        output_dir=output,
        no_brain=no_brain,
        incremental=incremental,
    )
    report = asyncio.run(mgr.run())

    console.print(Panel(
        f"[bold]ID:[/bold] {report.campaign_id}\n"
        f"[bold]Duration:[/bold] {report.duration_s:.0f}s\n"
        f"[bold]Completed:[/bold] {report.targets_completed}/{report.targets_total}\n"
        f"[bold]Failed:[/bold] {report.targets_failed}\n"
        f"[bold]Total Findings:[/bold] {report.total_findings}\n"
        f"[bold]HIGH/CRITICAL:[/bold] {report.total_high_crit}",
        title="[bold cyan]Campaign Complete[/bold cyan]",
        border_style="cyan",
    ))


@app.command()
def benchmark(
    lab: str = typer.Argument(..., help="Lab to benchmark: dvwa|juiceshop|webgoat|vampi|crapi|dvga|nodegoat|all"),
    findings: Optional[str] = typer.Option(None, "--findings", "-f", help="Path to findings JSON file"),
    findings_dir: str = typer.Option("output/scans", "--findings-dir", help="Directory to search for findings"),
    scan: bool = typer.Option(False, "--scan", help="Run scan against lab (requires Docker)"),
    report: bool = typer.Option(True, "--report/--no-report", help="Generate benchmark report"),
    calibrate: bool = typer.Option(False, "--calibrate", help="Show FP threshold calibration recommendation"),
    profile: str = typer.Option("aggressive", "--profile", "-p", help="Scan profile"),
    start_labs: bool = typer.Option(False, "--start-labs", help="Start Docker lab containers first"),
    stop_labs: bool = typer.Option(False, "--stop-labs", help="Stop Docker lab containers after"),
) -> None:
    """Benchmark scanner against vulnerable-by-design labs (TPR/FPR)."""
    show_banner()
    import asyncio
    from pathlib import Path

    from src.analysis.benchmark_lab import (
        BenchmarkEvaluator,
        BenchmarkReporter,
        BenchmarkScanner,
        CalibrationEngine,
        LabManager,
        load_findings,
        load_manifests,
    )

    manifests = load_manifests()
    evaluator = BenchmarkEvaluator(manifests)
    labs = evaluator.available_labs if lab == "all" else [lab]

    for lb in labs:
        if lb not in manifests:
            console.print(f"[bold red]Unknown lab:[/bold red] {lb}")
            raise typer.Exit(code=1)

    async def _run() -> None:
        lab_mgr = LabManager(manifests)

        if start_labs:
            console.print("[bold cyan]Starting Docker labs…[/bold cyan]")
            lab_mgr.start_labs(labs)
            ready = await lab_mgr.wait_for_ready(labs, max_wait=120)
            not_ready = [l for l, ok in ready.items() if not ok]
            if not_ready:
                console.print(f"[yellow]Labs not ready: {not_ready}[/yellow]")

        lab_findings: dict[str, list] = {}
        scanner = BenchmarkScanner(profile=profile, no_brain=True)

        for lb in labs:
            if findings:
                fp = Path(findings)
                if fp.exists():
                    lab_findings[lb] = load_findings(fp)
                    continue
            fd = Path(findings_dir)
            for candidate in [fd / f"{lb}_findings.json", fd / lb / "findings.json"]:
                if candidate.exists():
                    lab_findings[lb] = load_findings(candidate)
                    break
            else:
                if scan:
                    out = Path("output") / "benchmark" / lb
                    fpath = await scanner.scan_lab(lb, manifests[lb]["url"], out)
                    if fpath:
                        lab_findings[lb] = load_findings(fpath)

        if not lab_findings:
            console.print("[bold red]No findings to evaluate[/bold red]")
            raise typer.Exit(code=1)

        suite = evaluator.evaluate_suite(lab_findings)

        tpr_ok = suite.overall_tpr >= 0.80
        fpr_ok = suite.overall_fpr <= 0.20
        tpr_c = "green" if tpr_ok else "red"
        fpr_c = "green" if fpr_ok else "red"

        console.print(Panel(
            f"[bold]TPR (Recall):[/bold]  [{tpr_c}]{suite.overall_tpr:.1%}[/{tpr_c}]\n"
            f"[bold]Precision:[/bold]     [{fpr_c}]{suite.overall_precision:.1%}[/{fpr_c}]\n"
            f"[bold]FPR (FDR):[/bold]     [{fpr_c}]{suite.overall_fpr:.1%}[/{fpr_c}]\n"
            f"[bold]F1 Score:[/bold]      {suite.overall_f1:.3f}\n"
            f"TP={suite.total_tp}  FP={suite.total_fp}  FN={suite.total_fn}",
            title="[bold cyan]Benchmark Results[/bold cyan]",
            border_style="cyan",
        ))

        for r in suite.results:
            missed = f" [red]MISSED: {', '.join(r.missed_classes)}[/red]" if r.missed_classes else ""
            console.print(
                f"  {r.lab:12s}  TPR={r.tpr:.0%}  Prec={r.precision:.0%}  "
                f"FPR={r.fpr:.0%}  F1={r.f1:.2f}{missed}"
            )

        if calibrate:
            cal = CalibrationEngine()
            rec = cal.recommend(suite)
            console.print(f"\n[bold]Calibration:[/bold] {rec.reason}")

        if report:
            reporter = BenchmarkReporter()
            md_path = reporter.save(suite, Path("output/reports"))
            console.print(f"\n[dim]Report saved: {md_path}[/dim]")

        if stop_labs:
            lab_mgr.stop_labs()

    asyncio.run(_run())


@app.command()
def gui() -> None:
    """Masaüstü GUI'yi başlat (PySide6)."""
    show_banner()
    console.print("[bold cyan]GUI başlatılıyor...[/bold cyan]")

    from src.gui.app import WhaiGuiApp

    gui_app = WhaiGuiApp()
    raise SystemExit(gui_app.run())


@app.command()
def submit(
    report_path: str = typer.Argument(..., help="Rapor dosyası veya dizin yolu (JSON/MD)"),
    platform: str = typer.Option("hackerone", "--platform", "-p", help="Platform: hackerone | bugcrowd | generic"),
    draft: bool = typer.Option(True, "--draft/--no-draft", help="Draft olarak kaydet (gönderme)"),
    program: Optional[str] = typer.Option(None, "--program", help="Program handle/code (ör: 'vimeo', 'github')"),
) -> None:
    """Raporu bug bounty platformuna gönder (varsayılan: draft)."""
    show_banner()
    import json
    from pathlib import Path

    report_file = Path(report_path)
    if not report_file.exists():
        console.print(f"[bold red]Rapor bulunamadı:[/bold red] {report_path}")
        raise typer.Exit(code=1)

    # Load report
    try:
        if report_file.suffix == ".json":
            data = json.loads(report_file.read_text(encoding="utf-8"))
        else:
            data = {"body": report_file.read_text(encoding="utf-8")}
    except Exception as exc:
        console.print(f"[bold red]Rapor okunamadı:[/bold red] {exc}")
        raise typer.Exit(code=1)

    title = data.get("title", data.get("finding_title", report_file.stem))
    body = data.get("body", data.get("report_body", json.dumps(data, indent=2)))
    severity = str(data.get("severity") or "medium").lower()

    if platform == "hackerone":
        from src.reporting.platform_submit.hackerone_api import HackerOneAPI
        api = HackerOneAPI()
        report_obj = api.prepare_report(
            program_handle=program or "unknown",
            title=title, body=body, severity=severity,
        )
        if draft:
            console.print(Panel(
                f"[bold green]HackerOne Draft hazırlandı[/bold green]\n"
                f"Program: {program or 'unknown'}\n"
                f"Title: {title}\n"
                f"Severity: {severity}\n"
                f"[dim]Göndermek için --no-draft kullanın[/dim]",
                title="[bold]Draft Report[/bold]",
            ))
        else:
            result = asyncio.run(api.submit_report(report_obj, program or "unknown", human_confirmed=True))
            console.print(f"[bold]Gönderim sonucu:[/bold] {result}")
    elif platform == "bugcrowd":
        from src.reporting.platform_submit.bugcrowd_api import BugcrowdAPI
        api = BugcrowdAPI()
        submission = api.prepare_submission(
            program_code=program or "unknown",
            title=title, body=body, severity=severity,
        )
        if draft:
            console.print(Panel(
                f"[bold green]Bugcrowd Draft hazırlandı[/bold green]\n"
                f"Program: {program or 'unknown'}\n"
                f"Title: {title}",
                title="[bold]Draft Submission[/bold]",
            ))
        else:
            result = asyncio.run(api.submit(submission, program or "unknown", human_confirmed=True))
            console.print(f"[bold]Gönderim sonucu:[/bold] {result}")
    elif platform == "generic":
        from src.reporting.platform_submit.generic_api import GenericPlatformAPI
        api = GenericPlatformAPI()
        submission = api.prepare_submission(title=title, body=body, severity=severity)
        if draft:
            console.print(Panel(
                f"[bold green]Generic Draft hazırlandı[/bold green]\n"
                f"Title: {title}",
                title="[bold]Draft Submission[/bold]",
            ))
        else:
            result = asyncio.run(api.submit(submission, human_confirmed=True))
            console.print(f"[bold]Gönderim sonucu:[/bold] {result}")
    else:
        console.print(f"[bold red]Bilinmeyen platform:[/bold red] {platform}")
        console.print("Geçerli platformlar: hackerone, bugcrowd, generic")
        raise typer.Exit(code=1)


# ============================================================
# Entry Point
# ============================================================

if __name__ == "__main__":
    app()
