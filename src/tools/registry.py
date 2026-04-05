"""
WhiteHatHacker AI — Araç Kayıt ve Keşif Sistemi

Tüm güvenlik araçlarını merkezi olarak yönetir.
Araçlar otomatik keşfedilir, kaydedilir ve erişilebilirlik kontrol edilir.
"""

from __future__ import annotations

from typing import Any, Type

from loguru import logger

from src.tools.base import SecurityTool
from src.utils.constants import RiskLevel, ToolCategory


class ToolRegistry:
    """
    Güvenlik araçları merkezi kayıt sistemi.

    Singleton pattern ile tek bir registry instance'ı yönetir.
    Araçlar kategori, risk seviyesi ve erişilebilirlik bazında filtrelenebilir.

    Kullanım:
        registry = ToolRegistry()
        registry.register(NmapWrapper)

        nmap = registry.get("nmap")
        recon_tools = registry.get_by_category(ToolCategory.RECON_PORT)
        available = registry.get_available_tools()
    """

    _instance: ToolRegistry | None = None

    def __new__(cls) -> ToolRegistry:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
            cls._instance._tools = {}
            cls._instance._tool_classes = {}
            cls._instance._initialized = False
        return cls._instance

    def __init__(self) -> None:
        if not hasattr(self, '_tools'):
            self._tools: dict[str, SecurityTool] = {}
            self._tool_classes: dict[str, Type[SecurityTool]] = {}
            self._initialized = False

    def register(self, tool_class: Type[SecurityTool]) -> None:
        """
        Araç sınıfını kaydet.

        Args:
            tool_class: SecurityTool'dan türetilmiş sınıf
        """
        tool_instance = tool_class()
        name = tool_instance.name

        if name in self._tools:
            existing_class = self._tool_classes.get(name)
            if existing_class is tool_class:
                # Same class re-registered — silently skip (e.g., double import)
                return
            logger.warning(
                f"Tool '{name}' already registered by {existing_class.__name__}, "
                f"overwriting with {tool_class.__name__}"
            )

        self._tools[name] = tool_instance
        self._tool_classes[name] = tool_class

        available = tool_instance.is_available()
        logger.debug(
            f"Tool registered | name={name} | "
            f"category={tool_instance.category} | "
            f"available={available} | "
            f"risk={tool_instance.risk_level}"
        )

    def register_many(self, tool_classes: list[Type[SecurityTool]]) -> None:
        """Birden fazla aracı toplu kaydet."""
        for cls in tool_classes:
            try:
                self.register(cls)
            except Exception as exc:
                logger.warning(
                    f"Failed to register tool {cls.__name__}: {exc}"
                )

    def get(self, name: str) -> SecurityTool | None:
        """İsme göre araç döndür."""
        return self._tools.get(name)

    def get_or_raise(self, name: str) -> SecurityTool:
        """İsme göre araç döndür, yoksa hata fırlat."""
        tool = self._tools.get(name)
        if tool is None:
            raise KeyError(f"Tool '{name}' not registered")
        return tool

    def get_by_category(self, category: ToolCategory) -> list[SecurityTool]:
        """Kategoriye göre araçları döndür."""
        return [t for t in self._tools.values() if t.category == category]

    def get_by_risk_level(self, max_risk: RiskLevel) -> list[SecurityTool]:
        """Belirli risk seviyesine kadar olan araçları döndür."""
        risk_order = {
            RiskLevel.SAFE: 0,
            RiskLevel.LOW: 1,
            RiskLevel.MEDIUM: 2,
            RiskLevel.HIGH: 3,
            RiskLevel.CRITICAL: 4,
        }
        max_level = risk_order.get(max_risk, 4)
        return [
            t for t in self._tools.values()
            if risk_order.get(t.risk_level, 0) <= max_level
        ]

    def get_available_tools(self) -> list[SecurityTool]:
        """Sistemde kurulu ve erişilebilir araçları döndür."""
        return [t for t in self._tools.values() if t.is_available()]

    def get_unavailable_tools(self) -> list[SecurityTool]:
        """Sistemde kurulu olmayan araçları döndür."""
        return [t for t in self._tools.values() if not t.is_available()]

    def get_all(self) -> dict[str, SecurityTool]:
        """Tüm kayıtlı araçları döndür."""
        return self._tools.copy()

    def list_tools(self) -> list[dict[str, Any]]:
        """Tüm araçların özet bilgisini döndür."""
        tools_info = []
        for name, tool in sorted(self._tools.items()):
            tools_info.append({
                "name": name,
                "category": tool.category,
                "description": tool.description,
                "available": tool.is_available(),
                "risk_level": tool.risk_level,
                "requires_root": tool.requires_root,
            })
        return tools_info

    def health_check(self) -> dict[str, Any]:
        """Tüm araçların sağlık kontrolünü yap."""
        total = len(self._tools)
        available = len(self.get_available_tools())
        unavailable = len(self.get_unavailable_tools())

        by_category: dict[str, dict[str, int]] = {}
        for tool in self._tools.values():
            cat = str(tool.category)
            if cat not in by_category:
                by_category[cat] = {"total": 0, "available": 0}
            by_category[cat]["total"] += 1
            if tool.is_available():
                by_category[cat]["available"] += 1

        return {
            "total_registered": total,
            "available": available,
            "unavailable": unavailable,
            "availability_rate": round(available / max(1, total) * 100, 1),
            "by_category": by_category,
            "unavailable_tools": [t.name for t in self.get_unavailable_tools()],
        }

    @property
    def count(self) -> int:
        """Kayıtlı araç sayısını döndür."""
        return len(self._tools)

    def clear(self) -> None:
        """Tüm kayıtları temizle."""
        self._tools.clear()
        self._tool_classes.clear()

    def __len__(self) -> int:
        return len(self._tools)

    def __contains__(self, name: str) -> bool:
        return name in self._tools


# Global registry instance
tool_registry = ToolRegistry()

__all__ = ["ToolRegistry", "tool_registry"]
