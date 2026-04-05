"""
WhiteHatHacker AI — File Utilities

Dosya işlemleri, geçici dosya yönetimi, çıktı dizin yönetimi.
"""

from __future__ import annotations

import gzip
import hashlib
import json
import shutil
import tempfile
import time
from pathlib import Path
from typing import Any

from loguru import logger


# ============================================================
# Directory Management
# ============================================================

def ensure_output_dirs(base: str = "output") -> dict[str, Path]:
    """Çıktı dizinlerini oluştur ve yollarını döndür."""
    dirs = {
        "reports": Path(base) / "reports",
        "screenshots": Path(base) / "screenshots",
        "evidence": Path(base) / "evidence",
        "logs": Path(base) / "logs",
        "tmp": Path(base) / "tmp",
    }

    for name, path in dirs.items():
        path.mkdir(parents=True, exist_ok=True)

    return dirs


def create_session_dir(
    session_id: str,
    base: str = "output",
) -> Path:
    """Oturum bazlı çıktı dizini oluştur."""
    session_dir = Path(base) / "sessions" / session_id

    for sub in ("reports", "evidence", "screenshots", "tool_output", "logs"):
        (session_dir / sub).mkdir(parents=True, exist_ok=True)

    return session_dir


def cleanup_old_sessions(
    base: str = "output/sessions",
    max_age_days: int = 30,
) -> int:
    """Eski oturum dizinlerini temizle."""
    base_path = Path(base)
    if not base_path.exists():
        return 0

    cutoff = time.time() - (max_age_days * 86400)
    removed = 0

    for session_dir in base_path.iterdir():
        if session_dir.is_dir():
            try:
                mtime = session_dir.stat().st_mtime
                if mtime < cutoff:
                    shutil.rmtree(session_dir)
                    removed += 1
                    logger.debug(f"Removed old session: {session_dir.name}")
            except Exception as e:
                logger.warning(f"Failed to remove {session_dir}: {e}")

    if removed:
        logger.info(f"Cleaned up {removed} old session directories")

    return removed


# ============================================================
# File I/O
# ============================================================

def read_json(filepath: str | Path) -> Any:
    """JSON dosyasını oku."""
    path = Path(filepath)
    if not path.exists():
        return None

    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as e:
        logger.warning(f"Failed to read JSON {path}: {e}")
        return None


def write_json(
    data: Any,
    filepath: str | Path,
    indent: int = 2,
) -> bool:
    """JSON dosyasına yaz."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        path.write_text(
            json.dumps(data, indent=indent, ensure_ascii=False, default=str),
            encoding="utf-8",
        )
        return True
    except Exception as e:
        logger.error(f"Failed to write JSON {path}: {e}")
        return False


def read_lines(filepath: str | Path) -> list[str]:
    """Dosyayı satır satır oku (boş satırları atla)."""
    path = Path(filepath)
    if not path.exists():
        return []

    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        return [line.strip() for line in lines if line.strip()]
    except Exception as e:
        logger.warning(f"Failed to read lines from {path}: {e}")
        return []


def write_lines(lines: list[str], filepath: str | Path) -> bool:
    """Satır listesini dosyaya yaz."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        path.write_text("\n".join(lines) + "\n", encoding="utf-8")
        return True
    except Exception as e:
        logger.error(f"Failed to write lines to {path}: {e}")
        return False


def append_line(line: str, filepath: str | Path) -> bool:
    """Dosyaya satır ekle."""
    path = Path(filepath)
    path.parent.mkdir(parents=True, exist_ok=True)

    try:
        with open(path, "a", encoding="utf-8") as f:
            f.write(line.rstrip("\n") + "\n")
        return True
    except Exception as e:
        logger.error(f"Failed to append to {path}: {e}")
        return False


# ============================================================
# File Hashing
# ============================================================

def file_hash(filepath: str | Path, algorithm: str = "sha256") -> str:
    """Dosya hash'i hesapla."""
    path = Path(filepath)
    if not path.exists():
        return ""

    h = hashlib.new(algorithm)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


def file_md5(filepath: str | Path) -> str:
    """MD5 hash."""
    return file_hash(filepath, "md5")


def file_sha256(filepath: str | Path) -> str:
    """SHA-256 hash."""
    return file_hash(filepath, "sha256")


# ============================================================
# Compression
# ============================================================

def gzip_file(filepath: str | Path, remove_original: bool = False) -> str:
    """Dosyayı gzip ile sıkıştır."""
    path = Path(filepath)
    gz_path = path.with_suffix(path.suffix + ".gz")

    try:
        with open(path, "rb") as f_in:
            with gzip.open(gz_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

        if remove_original:
            path.unlink()

        logger.debug(f"Compressed: {path} → {gz_path}")
        return str(gz_path)
    except Exception as e:
        logger.error(f"Compression failed for {path}: {e}")
        return ""


def gunzip_file(filepath: str | Path) -> str:
    """Gzip dosyasını aç."""
    path = Path(filepath)
    out_path = path.with_suffix("")  # .gz'yi kaldır

    try:
        with gzip.open(path, "rb") as f_in:
            with open(out_path, "wb") as f_out:
                shutil.copyfileobj(f_in, f_out)

        return str(out_path)
    except Exception as e:
        logger.error(f"Decompression failed for {path}: {e}")
        return ""


# ============================================================
# Temporary Files
# ============================================================

def create_temp_file(
    content: str = "",
    suffix: str = ".txt",
    prefix: str = "whai_",
) -> str:
    """Geçici dosya oluştur ve yolunu döndür."""
    fd, path = tempfile.mkstemp(suffix=suffix, prefix=prefix)
    try:
        if content:
            with open(fd, "w", encoding="utf-8") as f:
                f.write(content)
        else:
            import os
            os.close(fd)
    except Exception as _exc:
        import os
        os.close(fd)

    return path


def create_temp_dir(prefix: str = "whai_") -> str:
    """Geçici dizin oluştur ve yolunu döndür."""
    return tempfile.mkdtemp(prefix=prefix)


# ============================================================
# Size Utilities
# ============================================================

def human_readable_size(size_bytes: int) -> str:
    """Byte → insan okunur boyut."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(size_bytes) < 1024:
            return f"{size_bytes:.1f} {unit}"
        size_bytes /= 1024  # type: ignore
    return f"{size_bytes:.1f} PB"


def dir_size(path: str | Path) -> int:
    """Dizin toplam boyutu (byte)."""
    total = 0
    for f in Path(path).rglob("*"):
        if f.is_file():
            total += f.stat().st_size
    return total


# ============================================================
# Wordlist Helpers
# ============================================================

def load_wordlist(filepath: str | Path) -> list[str]:
    """Wordlist dosyasını yükle (comment satırlarını atla)."""
    lines = read_lines(filepath)
    return [line for line in lines if not line.startswith("#")]


def merge_wordlists(
    files: list[str | Path],
    output: str | Path,
    deduplicate: bool = True,
) -> int:
    """Birden fazla wordlist'i birleştir."""
    all_words: list[str] = []

    for f in files:
        all_words.extend(load_wordlist(f))

    if deduplicate:
        # Sırayı koru, tekrarları sil
        seen: set[str] = set()
        unique: list[str] = []
        for w in all_words:
            if w not in seen:
                seen.add(w)
                unique.append(w)
        all_words = unique

    write_lines(all_words, output)
    logger.info(f"Merged {len(files)} wordlists → {len(all_words)} entries → {output}")
    return len(all_words)


__all__ = [
    "ensure_output_dirs",
    "create_session_dir",
    "cleanup_old_sessions",
    "read_json",
    "write_json",
    "read_lines",
    "write_lines",
    "append_line",
    "file_hash",
    "file_md5",
    "file_sha256",
    "gzip_file",
    "gunzip_file",
    "create_temp_file",
    "create_temp_dir",
    "human_readable_size",
    "dir_size",
    "load_wordlist",
    "merge_wordlists",
]
