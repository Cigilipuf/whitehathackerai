"""
WhiteHatHacker AI — PDF Report Formatter

Zafiyet raporlarını PDF formatında oluşturur.
Optional dependency: xhtml2pdf (pisa) veya weasyprint.
Fallback: Markdown → HTML → PDF dönüşümü.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from loguru import logger


class PdfFormatter:
    """
    PDF report formatter.

    xhtml2pdf veya weasyprint mevcutsa onları kullanır;
    yoksa HTML çıktıyı dosyaya yazar ve uyarı loglar.

    Usage:
        fmt = PdfFormatter()
        success = fmt.generate_pdf(report_data, "output/reports/finding.pdf")
    """

    def __init__(self) -> None:
        self._backend = self._detect_backend()

    @staticmethod
    def _detect_backend() -> str:
        """Mevcut PDF kütüphanesini tespit et."""
        try:
            import weasyprint  # noqa: F401
            return "weasyprint"
        except ImportError:
            pass

        try:
            import xhtml2pdf  # noqa: F401
            return "xhtml2pdf"
        except ImportError:
            pass

        return "none"

    @property
    def is_available(self) -> bool:
        return self._backend != "none"

    def generate_pdf(
        self,
        report: dict[str, Any],
        filepath: str,
    ) -> bool:
        """Raporu PDF'e çevir."""
        # HTML formatter ile önce HTML üret
        from src.reporting.formatters.html_formatter import HtmlFormatter

        html_content = HtmlFormatter().format_report(report)

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        if self._backend == "weasyprint":
            return self._generate_weasyprint(html_content, str(path))
        elif self._backend == "xhtml2pdf":
            return self._generate_xhtml2pdf(html_content, str(path))
        else:
            # Fallback: HTML dosyası olarak kaydet + uyarı
            html_path = path.with_suffix(".html")
            html_path.write_text(html_content, encoding="utf-8")
            logger.warning(
                f"PDF backend not available. HTML saved to {html_path}. "
                "Install weasyprint or xhtml2pdf for PDF generation: "
                "pip install weasyprint  # veya pip install xhtml2pdf"
            )
            return False

    def generate_pdf_from_html(self, html_content: str, filepath: str) -> bool:
        """Hazır HTML'den PDF üret."""
        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        if self._backend == "weasyprint":
            return self._generate_weasyprint(html_content, str(path))
        elif self._backend == "xhtml2pdf":
            return self._generate_xhtml2pdf(html_content, str(path))
        else:
            logger.warning("No PDF backend available")
            return False

    def generate_findings_pdf(
        self,
        findings: list[dict[str, Any]],
        filepath: str,
        session_id: str = "",
    ) -> bool:
        """Bulgu listesini PDF tablo olarak üret."""
        from src.reporting.formatters.html_formatter import HtmlFormatter

        html_content = HtmlFormatter().format_findings_table(findings, session_id)

        path = Path(filepath)
        path.parent.mkdir(parents=True, exist_ok=True)

        if self._backend == "weasyprint":
            return self._generate_weasyprint(html_content, str(path))
        elif self._backend == "xhtml2pdf":
            return self._generate_xhtml2pdf(html_content, str(path))
        else:
            html_path = path.with_suffix(".html")
            html_path.write_text(html_content, encoding="utf-8")
            logger.warning(f"PDF unavailable, HTML fallback saved: {html_path}")
            return False

    # --------- Backends ---------

    @staticmethod
    def _generate_weasyprint(html_content: str, filepath: str) -> bool:
        """WeasyPrint ile PDF üret."""
        try:
            import weasyprint

            doc = weasyprint.HTML(string=html_content)
            doc.write_pdf(filepath)
            logger.info(f"PDF report saved (weasyprint): {filepath}")
            return True
        except Exception as e:
            logger.error(f"WeasyPrint PDF generation failed: {e}")
            return False

    @staticmethod
    def _generate_xhtml2pdf(html_content: str, filepath: str) -> bool:
        """xhtml2pdf (pisa) ile PDF üret."""
        try:
            from xhtml2pdf import pisa

            with open(filepath, "wb") as f:
                status = pisa.CreatePDF(html_content, dest=f)

            if status.err:
                logger.error(f"xhtml2pdf reported {status.err} errors")
                return False

            logger.info(f"PDF report saved (xhtml2pdf): {filepath}")
            return True
        except Exception as e:
            logger.error(f"xhtml2pdf PDF generation failed: {e}")
            return False


__all__ = ["PdfFormatter"]
