"""
Delege Erişim Demo
===================
Bu demo, kullanıcının ajana sınırlı ve izlenebilir yetki
delege ettiği bir delegasyon sistemi gösterir. Token'lar
kapsamlı, süreli ve geri alınabilirdir.

Çalıştırma:
    python examples/delegated_access_demo.py
"""

import uuid
from datetime import datetime, timedelta, timezone
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class DelegatedToken:
    """Delege edilmiş yetki token'ı."""
    token_id: str
    agent_id: str
    user_id: str
    scopes: list[str]
    issued_at: datetime
    expires_at: datetime
    revoked: bool = False
    max_uses: Optional[int] = None
    use_count: int = 0

    def is_valid(self) -> bool:
        if self.revoked:
            return False
        if datetime.now(tz=timezone.utc) > self.expires_at:
            return False
        if self.max_uses is not None and self.use_count >= self.max_uses:
            return False
        return True

    def has_scope(self, required_scope: str) -> bool:
        return required_scope in self.scopes

    def use(self):
        self.use_count += 1

    def remaining_uses(self) -> Optional[int]:
        if self.max_uses is None:
            return None
        return max(0, self.max_uses - self.use_count)

    def remaining_time(self) -> timedelta:
        remaining = self.expires_at - datetime.now(tz=timezone.utc)
        return max(timedelta(0), remaining)


class DelegationManager:
    """Ajan delegasyon token'larını yöneten servis."""

    VALID_SCOPES = {
        "calendar.read": "Takvim okuma",
        "calendar.write": "Takvim yazma",
        "email.read": "E-posta okuma",
        "email.draft": "E-posta taslağı",
        "email.send": "E-posta gönderme",
        "contacts.read": "Kişi okuma",
        "files.read": "Dosya okuma",
    }

    def __init__(self, default_ttl_minutes: int = 60):
        self.tokens: dict[str, DelegatedToken] = {}
        self.default_ttl = default_ttl_minutes
        self.audit_log: list[dict] = []

    def create_delegation(
        self,
        agent_id: str,
        user_id: str,
        requested_scopes: list[str],
        ttl_minutes: Optional[int] = None,
        max_uses: Optional[int] = None,
    ) -> DelegatedToken:
        invalid = set(requested_scopes) - set(self.VALID_SCOPES.keys())
        if invalid:
            raise ValueError(f"Geçersiz scope'lar: {invalid}")

        ttl = ttl_minutes or self.default_ttl
        now = datetime.now(tz=timezone.utc)

        token = DelegatedToken(
            token_id=str(uuid.uuid4())[:12],
            agent_id=agent_id,
            user_id=user_id,
            scopes=requested_scopes,
            issued_at=now,
            expires_at=now + timedelta(minutes=ttl),
            max_uses=max_uses,
        )

        self.tokens[token.token_id] = token
        self._log("delegation_created", {
            "token_id": token.token_id,
            "agent_id": agent_id,
            "user_id": user_id,
            "scopes": requested_scopes,
            "ttl_minutes": ttl,
            "max_uses": max_uses,
        })

        return token

    def authorize(
        self,
        token_id: str,
        agent_id: str,
        required_scope: str,
    ) -> dict:
        token = self.tokens.get(token_id)
        if not token:
            self._log("auth_failed", {"reason": "token_not_found", "token_id": token_id})
            return {"authorized": False, "reason": "Token bulunamadı"}

        if token.agent_id != agent_id:
            self._log("auth_failed", {"reason": "agent_mismatch", "token_id": token_id})
            return {"authorized": False, "reason": "Token bu ajana ait değil"}

        if not token.is_valid():
            reason = "Bilinmeyen"
            if token.revoked:
                reason = "Token geri alındı"
            elif datetime.now(tz=timezone.utc) > token.expires_at:
                reason = "Token süresi doldu"
            elif token.max_uses is not None and token.use_count >= token.max_uses:
                reason = "Kullanım limiti aşıldı"

            self._log("auth_failed", {"reason": reason, "token_id": token_id})
            return {"authorized": False, "reason": reason}

        if not token.has_scope(required_scope):
            self._log("auth_failed", {
                "reason": "insufficient_scope",
                "required": required_scope,
                "available": token.scopes,
            })
            return {
                "authorized": False,
                "reason": f"Yetki kapsamı yetersiz. Gereken: {required_scope}, mevcut: {token.scopes}",
            }

        token.use()
        self._log("auth_success", {
            "token_id": token_id,
            "scope": required_scope,
            "remaining_uses": token.remaining_uses(),
        })

        return {
            "authorized": True,
            "user_id": token.user_id,
            "agent_id": token.agent_id,
            "scope": required_scope,
            "remaining_uses": token.remaining_uses(),
        }

    def revoke(self, token_id: str) -> bool:
        token = self.tokens.get(token_id)
        if token:
            token.revoked = True
            self._log("token_revoked", {"token_id": token_id})
            return True
        return False

    def revoke_all_for_agent(self, agent_id: str) -> int:
        count = 0
        for token in self.tokens.values():
            if token.agent_id == agent_id and not token.revoked:
                token.revoked = True
                count += 1
        if count:
            self._log("bulk_revoke", {"agent_id": agent_id, "count": count})
        return count

    def list_active_tokens(self, user_id: str = None) -> list[dict]:
        active = []
        for token in self.tokens.values():
            if not token.is_valid():
                continue
            if user_id and token.user_id != user_id:
                continue
            active.append({
                "token_id": token.token_id,
                "agent_id": token.agent_id,
                "scopes": token.scopes,
                "remaining_uses": token.remaining_uses(),
                "remaining_time": str(token.remaining_time()),
            })
        return active

    def _log(self, event: str, data: dict):
        self.audit_log.append({
            "timestamp": datetime.now(tz=timezone.utc).isoformat(),
            "event": event,
            **data,
        })


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("  DELEGE ERİŞİM DEMO")
    print("=" * 60)

    dm = DelegationManager(default_ttl_minutes=60)

    # 1. Delegasyon oluşturma
    print(f"\n{'─' * 40}")
    print("  1. DELEGASYON OLUŞTURMA")
    print(f"{'─' * 40}")

    token = dm.create_delegation(
        agent_id="agent-calendar-assistant",
        user_id="celal@sirket.com",
        requested_scopes=["calendar.read", "calendar.write", "email.draft"],
        ttl_minutes=60,
        max_uses=10,
    )

    print(f"\n  Token ID     : {token.token_id}")
    print(f"  Ajan         : {token.agent_id}")
    print(f"  Kullanıcı    : {token.user_id}")
    print(f"  Scope'lar    : {', '.join(token.scopes)}")
    print(f"  Süre         : 60 dakika")
    print(f"  Maks kullanım: {token.max_uses}")

    # 2. Yetkilendirme testleri
    print(f"\n{'─' * 40}")
    print("  2. YETKİLENDİRME TESTLERİ")
    print(f"{'─' * 40}")

    auth_tests = [
        {
            "name": "Takvim okuma (geçerli scope)",
            "scope": "calendar.read",
            "agent": "agent-calendar-assistant",
        },
        {
            "name": "E-posta taslağı (geçerli scope)",
            "scope": "email.draft",
            "agent": "agent-calendar-assistant",
        },
        {
            "name": "E-posta gönderme (yetersiz scope)",
            "scope": "email.send",
            "agent": "agent-calendar-assistant",
        },
        {
            "name": "Farklı ajan ile erişim",
            "scope": "calendar.read",
            "agent": "agent-shopping-assistant",
        },
    ]

    for test in auth_tests:
        result = dm.authorize(token.token_id, test["agent"], test["scope"])
        icon = "✅" if result["authorized"] else "❌"
        print(f"\n  {icon} {test['name']}")
        print(f"     Scope: {test['scope']} | Ajan: {test['agent']}")
        if result["authorized"]:
            print(f"     Kalan kullanım: {result['remaining_uses']}")
        else:
            print(f"     Neden: {result['reason']}")

    # 3. Kullanım limiti testi
    print(f"\n{'─' * 40}")
    print("  3. KULLANIM LİMİTİ TESTİ")
    print(f"{'─' * 40}")

    limited_token = dm.create_delegation(
        agent_id="agent-test",
        user_id="celal@sirket.com",
        requested_scopes=["calendar.read"],
        max_uses=3,
    )

    print(f"\n  Token: {limited_token.token_id} (maks 3 kullanım)")
    for i in range(4):
        result = dm.authorize(limited_token.token_id, "agent-test", "calendar.read")
        icon = "✅" if result["authorized"] else "❌"
        remaining = result.get("remaining_uses", 0)
        print(f"  {icon} Kullanım {i + 1}: {'Yetkilendirildi' if result['authorized'] else result['reason']} (kalan: {remaining})")

    # 4. Token iptali
    print(f"\n{'─' * 40}")
    print("  4. TOKEN İPTALİ")
    print(f"{'─' * 40}")

    revoke_token = dm.create_delegation(
        agent_id="agent-revoke-test",
        user_id="celal@sirket.com",
        requested_scopes=["calendar.read"],
    )

    print(f"\n  Token: {revoke_token.token_id}")
    result_before = dm.authorize(revoke_token.token_id, "agent-revoke-test", "calendar.read")
    print(f"  İptal öncesi: {'✅ Yetkilendirildi' if result_before['authorized'] else '❌'}")

    dm.revoke(revoke_token.token_id)
    print(f"  Token iptal edildi")

    result_after = dm.authorize(revoke_token.token_id, "agent-revoke-test", "calendar.read")
    print(f"  İptal sonrası: {'✅' if result_after['authorized'] else '❌ ' + result_after['reason']}")

    # 5. Aktif token listesi
    print(f"\n{'─' * 40}")
    print("  5. AKTİF TOKEN LİSTESİ")
    print(f"{'─' * 40}")

    active = dm.list_active_tokens(user_id="celal@sirket.com")
    print(f"\n  Aktif token sayısı: {len(active)}")
    for t in active:
        print(f"  - {t['token_id']}: ajan={t['agent_id']}, scope={t['scopes']}, kalan={t['remaining_uses']}")

    # 6. Denetim logu
    print(f"\n{'─' * 40}")
    print("  6. DENETİM LOGU")
    print(f"{'─' * 40}")

    print(f"\n  Toplam olay: {len(dm.audit_log)}")
    for log_entry in dm.audit_log[-5:]:
        print(f"  [{log_entry['event']}] {log_entry.get('token_id', log_entry.get('agent_id', ''))}")

    # Geçersiz scope testi
    print(f"\n{'─' * 40}")
    print("  7. GEÇERSİZ SCOPE TESTİ")
    print(f"{'─' * 40}")

    try:
        dm.create_delegation(
            agent_id="agent-bad",
            user_id="celal@sirket.com",
            requested_scopes=["calendar.read", "admin.all", "system.root"],
        )
    except ValueError as e:
        print(f"\n  ❌ Hata: {e}")
        print(f"  ℹ️  Geçerli scope'lar: {list(dm.VALID_SCOPES.keys())}")


if __name__ == "__main__":
    main()
