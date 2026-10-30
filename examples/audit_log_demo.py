"""
Denetim Logu Demo
==================
Bu demo, correlation ID tabanlı yapılandırılmış denetim logu
sistemi ve zincirlenmiş hash ile log bütünlük doğrulamasını gösterir.

Çalıştırma:
    python examples/audit_log_demo.py
"""

import uuid
import json
import hashlib
from datetime import datetime, timezone
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Optional


class EventType(str, Enum):
    REQUEST = "request"
    DECISION = "decision"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    APPROVAL_REQUEST = "approval_request"
    APPROVAL_RESPONSE = "approval_response"
    POLICY_CHECK = "policy_check"
    ERROR = "error"
    RESPONSE = "response"


@dataclass
class AuditEvent:
    """Denetim izi olayı."""
    event_id: str
    correlation_id: str
    timestamp: str
    event_type: EventType
    agent_id: str
    user_id: str
    data: dict
    parent_event_id: Optional[str] = None
    hash: Optional[str] = None

    def compute_hash(self, previous_hash: str = "") -> str:
        """Zincirlenmiş hash hesaplar."""
        content = json.dumps({
            "event_id": self.event_id,
            "correlation_id": self.correlation_id,
            "timestamp": self.timestamp,
            "event_type": self.event_type.value,
            "data": self.data,
            "previous_hash": previous_hash,
        }, sort_keys=True)
        self.hash = hashlib.sha256(content.encode()).hexdigest()
        return self.hash


class AuditLogger:
    """Yapılandırılmış denetim log sistemi."""

    def __init__(self, agent_id: str):
        self.agent_id = agent_id
        self.events: list[AuditEvent] = []
        self.last_hash: str = ""

    def _create_event(
        self,
        correlation_id: str,
        event_type: EventType,
        user_id: str,
        data: dict,
        parent_event_id: Optional[str] = None,
    ) -> AuditEvent:
        event = AuditEvent(
            event_id=str(uuid.uuid4())[:8],
            correlation_id=correlation_id,
            timestamp=datetime.now(tz=timezone.utc).isoformat(),
            event_type=event_type,
            agent_id=self.agent_id,
            user_id=user_id,
            data=data,
            parent_event_id=parent_event_id,
        )
        self.last_hash = event.compute_hash(self.last_hash)
        self.events.append(event)
        return event

    def log_request(self, correlation_id: str, user_id: str, request: str) -> AuditEvent:
        return self._create_event(
            correlation_id, EventType.REQUEST, user_id,
            {"request": request},
        )

    def log_decision(
        self, correlation_id: str, user_id: str,
        decision: str, reasoning: str, parent_event_id: str,
    ) -> AuditEvent:
        return self._create_event(
            correlation_id, EventType.DECISION, user_id,
            {"decision": decision, "reasoning": reasoning},
            parent_event_id,
        )

    def log_tool_call(
        self, correlation_id: str, user_id: str,
        tool_name: str, parameters: dict, parent_event_id: str,
    ) -> AuditEvent:
        return self._create_event(
            correlation_id, EventType.TOOL_CALL, user_id,
            {"tool": tool_name, "parameters": parameters},
            parent_event_id,
        )

    def log_tool_result(
        self, correlation_id: str, user_id: str,
        tool_name: str, success: bool, parent_event_id: str,
    ) -> AuditEvent:
        return self._create_event(
            correlation_id, EventType.TOOL_RESULT, user_id,
            {"tool": tool_name, "success": success},
            parent_event_id,
        )

    def log_policy_check(
        self, correlation_id: str, user_id: str,
        policy: str, result: str, parent_event_id: str,
    ) -> AuditEvent:
        return self._create_event(
            correlation_id, EventType.POLICY_CHECK, user_id,
            {"policy": policy, "result": result},
            parent_event_id,
        )

    def log_approval(
        self, correlation_id: str, user_id: str,
        action: str, status: str, parent_event_id: str,
    ) -> AuditEvent:
        return self._create_event(
            correlation_id, EventType.APPROVAL_RESPONSE, user_id,
            {"action": action, "status": status},
            parent_event_id,
        )

    def get_trace(self, correlation_id: str) -> list[dict]:
        """Bir correlation ID'ye ait tüm olayları döndürür."""
        return [
            asdict(e) for e in self.events
            if e.correlation_id == correlation_id
        ]

    def verify_integrity(self) -> dict:
        """Log zincirinin bütünlüğünü doğrular."""
        if not self.events:
            return {"valid": True, "checked": 0}

        previous_hash = ""
        for i, event in enumerate(self.events):
            content = json.dumps({
                "event_id": event.event_id,
                "correlation_id": event.correlation_id,
                "timestamp": event.timestamp,
                "event_type": event.event_type.value,
                "data": event.data,
                "previous_hash": previous_hash,
            }, sort_keys=True)
            expected = hashlib.sha256(content.encode()).hexdigest()

            if event.hash != expected:
                return {
                    "valid": False,
                    "broken_at_index": i,
                    "event_id": event.event_id,
                    "message": "Hash uyumsuzluğu tespit edildi — log manipülasyonu!",
                }
            previous_hash = event.hash

        return {"valid": True, "checked": len(self.events), "message": "Tüm loglar bütünlük kontrolünü geçti"}


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("  DENETİM LOGU DEMO")
    print("=" * 60)

    logger = AuditLogger(agent_id="agent-calendar-assistant")
    corr_id = "demo-" + str(uuid.uuid4())[:8]
    user_id = "celal@sirket.com"

    # Senaryo: Kullanıcı toplantı ayarlamak ve davet göndermek istiyor
    print(f"\n  Correlation ID: {corr_id}")
    print(f"  Senaryo: Toplantı ayarlama ve davet gönderme")
    print(f"  {'─' * 50}")

    # 1. İstek
    e1 = logger.log_request(corr_id, user_id, "Yarın 14:00'te Ahmet ile toplantı ayarla ve davet gönder")
    print(f"\n  [{e1.event_type.value}] {e1.data['request']}")

    # 2. Karar: Takvim kontrol et
    e2 = logger.log_decision(corr_id, user_id, "Takvimi kontrol et", "Uygun saat doğrulanmalı", e1.event_id)
    print(f"  [{e2.event_type.value}] {e2.data['decision']} — {e2.data['reasoning']}")

    # 3. Araç çağrısı: read_calendar
    e3 = logger.log_tool_call(corr_id, user_id, "read_calendar", {"date": "2026-03-15"}, e2.event_id)
    print(f"  [{e3.event_type.value}] {e3.data['tool']}({e3.data['parameters']})")

    # 4. Araç sonucu
    e4 = logger.log_tool_result(corr_id, user_id, "read_calendar", True, e3.event_id)
    print(f"  [{e4.event_type.value}] {e4.data['tool']} → başarılı: {e4.data['success']}")

    # 5. Politika kontrolü: create_event
    e5 = logger.log_policy_check(corr_id, user_id, "create_event", "allowed (tier 1)", e4.event_id)
    print(f"  [{e5.event_type.value}] {e5.data['policy']} → {e5.data['result']}")

    # 6. Araç çağrısı: create_event
    e6 = logger.log_tool_call(corr_id, user_id, "create_event", {"date": "2026-03-15", "time": "14:00", "title": "Ahmet ile Toplantı"}, e5.event_id)
    print(f"  [{e6.event_type.value}] {e6.data['tool']}({e6.data['parameters']})")

    # 7. Politika kontrolü: send_email
    e7 = logger.log_policy_check(corr_id, user_id, "send_email", "approval_required (tier 2)", e6.event_id)
    print(f"  [{e7.event_type.value}] {e7.data['policy']} → {e7.data['result']}")

    # 8. Onay
    e8 = logger.log_approval(corr_id, user_id, "send_email", "approved", e7.event_id)
    print(f"  [{e8.event_type.value}] {e8.data['action']} → {e8.data['status']}")

    # 9. Araç çağrısı: send_email
    e9 = logger.log_tool_call(corr_id, user_id, "send_email", {"to": "ahmet@sirket.com", "subject": "Toplantı Daveti"}, e8.event_id)
    print(f"  [{e9.event_type.value}] {e9.data['tool']}({e9.data['parameters']})")

    # 10. Sonuç
    e10 = logger.log_tool_result(corr_id, user_id, "send_email", True, e9.event_id)
    print(f"  [{e10.event_type.value}] {e10.data['tool']} → başarılı: {e10.data['success']}")

    # İz sürme
    print(f"\n{'=' * 60}")
    print("  İZ SÜRME (TRACE)")
    print(f"{'=' * 60}")

    trace = logger.get_trace(corr_id)
    print(f"\n  Correlation ID: {corr_id}")
    print(f"  Toplam olay: {len(trace)}")
    for i, event in enumerate(trace):
        print(f"  {i + 1}. [{event['event_type']}] hash: ...{event['hash'][-12:]}")

    # Bütünlük doğrulama
    print(f"\n{'=' * 60}")
    print("  BÜTÜNLÜK DOĞRULAMA")
    print(f"{'=' * 60}")

    integrity = logger.verify_integrity()
    print(f"\n  Sonuç: {'✅ Geçerli' if integrity['valid'] else '❌ Geçersiz'}")
    print(f"  Kontrol edilen: {integrity['checked']} olay")
    print(f"  Mesaj: {integrity['message']}")

    # Manipülasyon tespiti demo
    print(f"\n{'=' * 60}")
    print("  MANİPÜLASYON TESPİTİ DEMO")
    print(f"{'=' * 60}")

    print(f"\n  3. olayın verisini değiştiriyoruz (simülasyon)...")
    original_data = logger.events[2].data.copy()
    logger.events[2].data["parameters"]["date"] = "2026-12-31"

    tampered = logger.verify_integrity()
    print(f"  Sonuç: {'✅ Geçerli' if tampered['valid'] else '❌ Geçersiz'}")
    if not tampered["valid"]:
        print(f"  Kırılma noktası: olay #{tampered['broken_at_index'] + 1}")
        print(f"  Mesaj: {tampered['message']}")

    logger.events[2].data = original_data


if __name__ == "__main__":
    main()
