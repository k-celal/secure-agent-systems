"""
Araç İzin Koruma Demo
======================
Bu demo, araç çağrılarını merkezi bir güvenlik katmanından
geçiren izin kontrol sistemini gösterir.

Çalıştırma:
    python examples/tool_permission_guard_demo.py
"""

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional, Callable


class ToolRiskLevel(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass
class ToolDefinition:
    """Araç tanımı ve güvenlik yapılandırması."""
    name: str
    description: str
    risk_level: ToolRiskLevel
    requires_approval: bool
    allowed_roles: list[str]
    rate_limit: Optional[int] = None  # dakika başına maks çağrı


@dataclass
class ToolRegistry:
    """Araçları ve izinlerini yöneten merkezi kayıt."""
    tools: dict[str, ToolDefinition] = field(default_factory=dict)

    def register(self, tool: ToolDefinition):
        self.tools[tool.name] = tool

    def is_allowed(self, tool_name: str, user_role: str) -> bool:
        if tool_name not in self.tools:
            return False
        return user_role in self.tools[tool_name].allowed_roles

    def requires_approval(self, tool_name: str) -> bool:
        if tool_name not in self.tools:
            return True
        return self.tools[tool_name].requires_approval

    def get_risk_level(self, tool_name: str) -> ToolRiskLevel:
        if tool_name not in self.tools:
            return ToolRiskLevel.CRITICAL
        return self.tools[tool_name].risk_level


@dataclass
class ToolFirewall:
    """Tüm araç çağrılarını kontrol eden merkezi güvenlik katmanı."""
    registry: ToolRegistry
    call_counts: dict[str, int] = field(default_factory=dict)

    def execute(
        self,
        tool_name: str,
        params: dict,
        user_role: str,
    ) -> dict:
        # 1. Araç varlık kontrolü
        if tool_name not in self.registry.tools:
            return {
                "status": "denied",
                "reason": f"Bilinmeyen araç: {tool_name}",
            }

        tool = self.registry.tools[tool_name]

        # 2. Rol izin kontrolü
        if not self.registry.is_allowed(tool_name, user_role):
            return {
                "status": "denied",
                "reason": f"'{user_role}' rolü '{tool_name}' aracını kullanamaz",
                "allowed_roles": tool.allowed_roles,
            }

        # 3. Rate limit kontrolü
        if tool.rate_limit:
            count = self.call_counts.get(tool_name, 0)
            if count >= tool.rate_limit:
                return {
                    "status": "denied",
                    "reason": f"Oran sınırı aşıldı: {count}/{tool.rate_limit}",
                }

        # 4. Onay kontrolü
        if tool.requires_approval:
            return {
                "status": "approval_required",
                "tool": tool_name,
                "risk_level": tool.risk_level.value,
                "message": "Bu işlem kullanıcı onayı gerektiriyor",
            }

        # 5. Çalıştır
        self.call_counts[tool_name] = self.call_counts.get(tool_name, 0) + 1
        return {
            "status": "executed",
            "tool": tool_name,
            "risk_level": tool.risk_level.value,
            "params": params,
        }


def create_demo_registry() -> ToolRegistry:
    """Demo için araç kayıtı oluşturur."""
    registry = ToolRegistry()

    registry.register(ToolDefinition(
        name="read_calendar",
        description="Takvim etkinliklerini okur",
        risk_level=ToolRiskLevel.LOW,
        requires_approval=False,
        allowed_roles=["user", "assistant"],
        rate_limit=100,
    ))

    registry.register(ToolDefinition(
        name="check_availability",
        description="Müsaitlik durumunu kontrol eder",
        risk_level=ToolRiskLevel.LOW,
        requires_approval=False,
        allowed_roles=["user", "assistant"],
        rate_limit=50,
    ))

    registry.register(ToolDefinition(
        name="create_event",
        description="Takvim etkinliği oluşturur",
        risk_level=ToolRiskLevel.MEDIUM,
        requires_approval=False,
        allowed_roles=["assistant"],
        rate_limit=20,
    ))

    registry.register(ToolDefinition(
        name="draft_email",
        description="E-posta taslağı oluşturur",
        risk_level=ToolRiskLevel.MEDIUM,
        requires_approval=False,
        allowed_roles=["assistant"],
        rate_limit=20,
    ))

    registry.register(ToolDefinition(
        name="send_email",
        description="E-posta gönderir",
        risk_level=ToolRiskLevel.HIGH,
        requires_approval=True,
        allowed_roles=["assistant"],
        rate_limit=10,
    ))

    registry.register(ToolDefinition(
        name="delete_all_events",
        description="Tüm takvim etkinliklerini siler",
        risk_level=ToolRiskLevel.CRITICAL,
        requires_approval=True,
        allowed_roles=["admin"],
        rate_limit=1,
    ))

    return registry


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("  ARAÇ İZİN KORUMA DEMO")
    print("=" * 60)

    registry = create_demo_registry()
    firewall = ToolFirewall(registry=registry)

    test_cases = [
        {
            "name": "Takvim okuma (assistant) — izin verilmeli",
            "tool": "read_calendar",
            "params": {"date": "2026-03-15"},
            "role": "assistant",
        },
        {
            "name": "E-posta gönderme (assistant) — onay gerekli",
            "tool": "send_email",
            "params": {"to": "ahmet@sirket.com", "subject": "Test"},
            "role": "assistant",
        },
        {
            "name": "Tüm etkinlikleri silme (assistant) — reddedilmeli",
            "tool": "delete_all_events",
            "params": {"confirm": True},
            "role": "assistant",
        },
        {
            "name": "Tüm etkinlikleri silme (admin) — onay gerekli",
            "tool": "delete_all_events",
            "params": {"confirm": True},
            "role": "admin",
        },
        {
            "name": "Bilinmeyen araç — reddedilmeli",
            "tool": "execute_code",
            "params": {"code": "import os; os.system('rm -rf /')"},
            "role": "assistant",
        },
        {
            "name": "Etkinlik oluşturma (user) — reddedilmeli",
            "tool": "create_event",
            "params": {"title": "Toplantı"},
            "role": "user",
        },
        {
            "name": "Etkinlik oluşturma (assistant) — izin verilmeli",
            "tool": "create_event",
            "params": {"title": "Toplantı", "date": "2026-03-15"},
            "role": "assistant",
        },
    ]

    for tc in test_cases:
        result = firewall.execute(tc["tool"], tc["params"], tc["role"])
        status_icon = {
            "executed": "✅",
            "approval_required": "⚠️",
            "denied": "❌",
        }.get(result["status"], "❓")

        print(f"\n{status_icon} Test: {tc['name']}")
        print(f"   Araç: {tc['tool']} | Rol: {tc['role']}")
        print(f"   Sonuç: {result['status']}")
        if result.get("reason"):
            print(f"   Neden: {result['reason']}")
        if result.get("risk_level"):
            print(f"   Risk: {result['risk_level']}")

    # Rate limit demo
    print(f"\n{'=' * 60}")
    print("  RATE LIMIT DEMO")
    print(f"{'=' * 60}")

    rate_firewall = ToolFirewall(registry=registry)
    print("\n  read_calendar aracını 5 kez çağırıyoruz (limit: 100):")
    for i in range(5):
        result = rate_firewall.execute("read_calendar", {"date": f"2026-03-{15 + i}"}, "assistant")
        print(f"   Çağrı {i + 1}: {result['status']}")

    print("\n  Kayıtlı araçlar ve risk seviyeleri:")
    for name, tool in registry.tools.items():
        print(f"   {name}: risk={tool.risk_level.value}, onay={tool.requires_approval}, roller={tool.allowed_roles}")


if __name__ == "__main__":
    main()
