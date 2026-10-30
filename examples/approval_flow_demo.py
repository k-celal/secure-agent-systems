"""
Onay Akışı Demo
=================
Bu demo, risk kademelendirmesine dayalı bir onay akışı
sistemini gösterir. Aksiyonlar risk seviyesine göre
otomatik, bildirimli veya onay gerekli olarak sınıflandırılır.

Çalıştırma:
    python examples/approval_flow_demo.py
"""

import uuid
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional


class RiskTier(int, Enum):
    TIER_0 = 0  # Otomatik
    TIER_1 = 1  # Bildirim
    TIER_2 = 2  # Onay gerekli
    TIER_3 = 3  # Çift onay
    TIER_4 = 4  # Yönetici onayı


class Reversibility(str, Enum):
    FULLY_REVERSIBLE = "fully_reversible"
    PARTIALLY_REVERSIBLE = "partially_reversible"
    IRREVERSIBLE = "irreversible"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EXPIRED = "expired"
    AUTO_APPROVED = "auto_approved"


@dataclass
class ActionClassification:
    """Aksiyonun risk sınıflandırması."""
    action_name: str
    risk_tier: RiskTier
    reversibility: Reversibility
    requires_human_approval: bool
    explanation_required: bool = False
    approval_timeout_minutes: int = 15


@dataclass
class ApprovalRequest:
    """Onay talebi."""
    request_id: str
    action_name: str
    parameters: dict
    risk_tier: RiskTier
    explanation: str
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus = ApprovalStatus.PENDING
    decided_by: Optional[str] = None
    decision_at: Optional[datetime] = None


@dataclass
class ActionExplanation:
    """Kullanıcıya gösterilecek aksiyon açıklaması."""
    action: str
    target: str
    reason: str
    impact: str
    reversibility: str
    alternatives: list[str]

    def format(self) -> str:
        lines = [
            f"  Aksiyon    : {self.action}",
            f"  Hedef      : {self.target}",
            f"  Neden      : {self.reason}",
            f"  Etki       : {self.impact}",
            f"  Geri Alım  : {self.reversibility}",
            f"  Alternatifler: {', '.join(self.alternatives)}",
        ]
        return "\n".join(lines)


ACTION_CATALOG: dict[str, ActionClassification] = {
    "read_calendar": ActionClassification(
        action_name="read_calendar",
        risk_tier=RiskTier.TIER_0,
        reversibility=Reversibility.FULLY_REVERSIBLE,
        requires_human_approval=False,
    ),
    "list_emails": ActionClassification(
        action_name="list_emails",
        risk_tier=RiskTier.TIER_0,
        reversibility=Reversibility.FULLY_REVERSIBLE,
        requires_human_approval=False,
    ),
    "draft_email": ActionClassification(
        action_name="draft_email",
        risk_tier=RiskTier.TIER_1,
        reversibility=Reversibility.FULLY_REVERSIBLE,
        requires_human_approval=False,
    ),
    "create_event": ActionClassification(
        action_name="create_event",
        risk_tier=RiskTier.TIER_1,
        reversibility=Reversibility.FULLY_REVERSIBLE,
        requires_human_approval=False,
    ),
    "send_email": ActionClassification(
        action_name="send_email",
        risk_tier=RiskTier.TIER_2,
        reversibility=Reversibility.IRREVERSIBLE,
        requires_human_approval=True,
        explanation_required=True,
        approval_timeout_minutes=15,
    ),
    "delete_event": ActionClassification(
        action_name="delete_event",
        risk_tier=RiskTier.TIER_2,
        reversibility=Reversibility.PARTIALLY_REVERSIBLE,
        requires_human_approval=True,
        explanation_required=True,
        approval_timeout_minutes=10,
    ),
    "bulk_send_email": ActionClassification(
        action_name="bulk_send_email",
        risk_tier=RiskTier.TIER_3,
        reversibility=Reversibility.IRREVERSIBLE,
        requires_human_approval=True,
        explanation_required=True,
        approval_timeout_minutes=5,
    ),
    "delete_account": ActionClassification(
        action_name="delete_account",
        risk_tier=RiskTier.TIER_4,
        reversibility=Reversibility.IRREVERSIBLE,
        requires_human_approval=True,
        explanation_required=True,
        approval_timeout_minutes=5,
    ),
}


class ApprovalEngine:
    """Risk bazlı onay motoru."""

    def __init__(self):
        self.requests: dict[str, ApprovalRequest] = {}

    def classify_action(self, action_name: str) -> ActionClassification:
        classification = ACTION_CATALOG.get(action_name)
        if not classification:
            return ActionClassification(
                action_name=action_name,
                risk_tier=RiskTier.TIER_3,
                reversibility=Reversibility.IRREVERSIBLE,
                requires_human_approval=True,
                explanation_required=True,
            )
        return classification

    def process_action(
        self,
        action_name: str,
        parameters: dict,
        explanation: str = "",
    ) -> dict:
        classification = self.classify_action(action_name)

        if classification.risk_tier == RiskTier.TIER_0:
            return {
                "decision": "auto_approved",
                "tier": classification.risk_tier.value,
                "message": "Düşük riskli aksiyon — otomatik onay",
            }

        if classification.risk_tier == RiskTier.TIER_1:
            return {
                "decision": "auto_approved_with_notification",
                "tier": classification.risk_tier.value,
                "message": "Orta-düşük riskli aksiyon — bildirim ile otomatik onay",
            }

        now = datetime.now(tz=timezone.utc)
        request = ApprovalRequest(
            request_id=str(uuid.uuid4())[:8],
            action_name=action_name,
            parameters=parameters,
            risk_tier=classification.risk_tier,
            explanation=explanation,
            created_at=now,
            expires_at=now + timedelta(minutes=classification.approval_timeout_minutes),
        )
        self.requests[request.request_id] = request

        tier_label = {
            RiskTier.TIER_2: "Kullanıcı onayı gerekli",
            RiskTier.TIER_3: "Çift onay gerekli",
            RiskTier.TIER_4: "Yönetici onayı gerekli",
        }.get(classification.risk_tier, "Onay gerekli")

        return {
            "decision": "approval_required",
            "request_id": request.request_id,
            "tier": classification.risk_tier.value,
            "tier_label": tier_label,
            "timeout_minutes": classification.approval_timeout_minutes,
            "explanation_required": classification.explanation_required,
        }

    def approve(self, request_id: str, approved_by: str = "user") -> dict:
        request = self.requests.get(request_id)
        if not request:
            return {"success": False, "reason": "Talep bulunamadı"}

        if datetime.now(tz=timezone.utc) > request.expires_at:
            request.status = ApprovalStatus.EXPIRED
            return {"success": False, "reason": "Onay süresi doldu"}

        request.status = ApprovalStatus.APPROVED
        request.decided_by = approved_by
        request.decision_at = datetime.now(tz=timezone.utc)
        return {
            "success": True,
            "message": f"Aksiyon onaylandı: {request.action_name}",
        }

    def reject(self, request_id: str, rejected_by: str = "user") -> dict:
        request = self.requests.get(request_id)
        if not request:
            return {"success": False, "reason": "Talep bulunamadı"}

        request.status = ApprovalStatus.REJECTED
        request.decided_by = rejected_by
        request.decision_at = datetime.now(tz=timezone.utc)
        return {
            "success": True,
            "message": f"Aksiyon reddedildi: {request.action_name}",
        }


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("  ONAY AKIŞI DEMO")
    print("=" * 60)

    engine = ApprovalEngine()

    # Farklı risk seviyelerindeki aksiyonları test et
    test_actions = [
        {
            "action": "read_calendar",
            "params": {"date": "2026-03-15"},
            "explanation": "",
        },
        {
            "action": "draft_email",
            "params": {"to": "ahmet@sirket.com", "subject": "Hatırlatma"},
            "explanation": "",
        },
        {
            "action": "send_email",
            "params": {"to": "ahmet@sirket.com", "subject": "Toplantı Daveti"},
            "explanation": "Kullanıcı yarınki toplantı için davet göndermek istiyor",
        },
        {
            "action": "bulk_send_email",
            "params": {"to_list": ["a@s.com", "b@s.com", "c@s.com"], "subject": "Duyuru"},
            "explanation": "Tüm ekibe duyuru gönderme",
        },
        {
            "action": "delete_account",
            "params": {"account_id": "user-123"},
            "explanation": "Kullanıcı hesabını silme",
        },
        {
            "action": "unknown_action",
            "params": {},
            "explanation": "",
        },
    ]

    print("\n  Risk Kademelendirme Sonuçları:")
    print("  " + "-" * 56)

    for ta in test_actions:
        result = engine.process_action(
            action_name=ta["action"],
            parameters=ta["params"],
            explanation=ta["explanation"],
        )

        tier_icons = {
            0: "🟢",
            1: "🔵",
            2: "🟡",
            3: "🟠",
            4: "🔴",
        }
        icon = tier_icons.get(result["tier"], "❓")

        print(f"\n  {icon} Aksiyon: {ta['action']}")
        print(f"     Kademe: {result['tier']} | Karar: {result['decision']}")
        if result.get("message"):
            print(f"     Mesaj: {result['message']}")
        if result.get("tier_label"):
            print(f"     Etiket: {result['tier_label']}")
        if result.get("request_id"):
            print(f"     Talep ID: {result['request_id']}")

    # Onay/red demo
    print(f"\n{'=' * 60}")
    print("  ONAY / RED DEMO")
    print(f"{'=' * 60}")

    send_result = engine.process_action(
        action_name="send_email",
        parameters={"to": "test@sirket.com", "subject": "Demo"},
        explanation="Demo amaçlı e-posta",
    )
    request_id = send_result.get("request_id")

    if request_id:
        print(f"\n  Onay talebi oluşturuldu: {request_id}")

        # Açıkla-sonra-yap kalıbı
        explanation = ActionExplanation(
            action="E-posta Gönder",
            target="test@sirket.com",
            reason="Demo amaçlı e-posta gönderimi",
            impact="Alıcı bir e-posta alacak",
            reversibility="Geri alınamaz — gönderilen e-posta geri çekilemez",
            alternatives=["Taslak olarak kaydet", "İptal et"],
        )
        print(f"\n  Açıklama (explain-before-act):")
        print(explanation.format())

        # Onayla
        approval = engine.approve(request_id, approved_by="demo_user")
        print(f"\n  Onay sonucu: {approval['message']}")

    # Red demo
    reject_result = engine.process_action(
        action_name="delete_account",
        parameters={"account_id": "user-456"},
        explanation="Test hesabı silme",
    )
    reject_id = reject_result.get("request_id")
    if reject_id:
        rejection = engine.reject(reject_id, rejected_by="demo_user")
        print(f"  Red sonucu: {rejection['message']}")

    # Kademe tablosu
    print(f"\n{'=' * 60}")
    print("  RİSK KADEME TABLOSU")
    print(f"{'=' * 60}")
    print(f"\n  {'Kademe':<10} {'Akış':<25} {'Örnekler'}")
    print(f"  {'-' * 60}")
    print(f"  {'Tier 0':<10} {'Otomatik':<25} {'Takvim okuma, arama'}")
    print(f"  {'Tier 1':<10} {'Bildirim + otomatik':<25} {'Taslak, etkinlik oluşturma'}")
    print(f"  {'Tier 2':<10} {'Onay gerekli':<25} {'E-posta gönderme'}")
    print(f"  {'Tier 3':<10} {'Çift onay':<25} {'Toplu e-posta, dosya silme'}")
    print(f"  {'Tier 4':<10} {'Yönetici onayı':<25} {'Hesap silme, yetki değişikliği'}")


if __name__ == "__main__":
    main()
