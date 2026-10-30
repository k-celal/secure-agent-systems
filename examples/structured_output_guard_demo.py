"""
Yapılandırılmış Çıktı Koruma Demo
===================================
Bu demo, ajan çıktısını serbest metin yerine yapılandırılmış
şema ile doğrulayarak injection etkisini azaltan bir sistemi gösterir.

Çalıştırma:
    python examples/structured_output_guard_demo.py
"""

from dataclasses import dataclass
from enum import Enum
from typing import Optional
import re
import json


class ActionType(str, Enum):
    SEND_EMAIL = "send_email"
    CREATE_EVENT = "create_event"
    DRAFT_EMAIL = "draft_email"
    READ_CALENDAR = "read_calendar"
    SUMMARIZE = "summarize"


BLOCKED_DOMAINS = [
    "evil.com", "malicious.org", "exfil.io",
    "tempmail.com", "throwaway.email", "guerrillamail.com",
]

SENSITIVE_PATTERNS = [
    (r"(?i)password\s*[:=]\s*\S+", "parola"),
    (r"(?i)api[_-]?key\s*[:=]\s*\S+", "api_anahtari"),
    (r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b", "kredi_karti"),
    (r"\b[1-9]\d{10}\b", "tc_kimlik"),
]


@dataclass
class ValidationError:
    field: str
    message: str


@dataclass
class AgentAction:
    """Ajanın gerçekleştirebileceği aksiyonların şeması."""
    action: ActionType
    target_email: Optional[str] = None
    subject: Optional[str] = None
    body: Optional[str] = None
    date: Optional[str] = None
    time: Optional[str] = None
    requires_approval: bool = True


def validate_email(email: str) -> list[ValidationError]:
    """E-posta adresini doğrular."""
    errors = []
    email_pattern = r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$"
    if not re.match(email_pattern, email):
        errors.append(ValidationError("target_email", f"Geçersiz e-posta formatı: {email}"))
        return errors

    domain = email.split("@")[1].lower()
    if domain in BLOCKED_DOMAINS:
        errors.append(ValidationError("target_email", f"Engellenen alan adı: {domain}"))

    return errors


def validate_body(body: str) -> list[ValidationError]:
    """E-posta gövdesinde hassas veri olup olmadığını kontrol eder."""
    errors = []
    for pattern, data_type in SENSITIVE_PATTERNS:
        if re.search(pattern, body):
            errors.append(ValidationError(
                "body",
                f"E-posta gövdesinde hassas veri tespit edildi: {data_type}",
            ))
    return errors


def validate_agent_output(raw_output: dict) -> tuple[Optional[AgentAction], list[ValidationError]]:
    """Ajan çıktısını şemaya karşı doğrular."""
    errors = []

    # Aksiyon tipi kontrolü
    action_str = raw_output.get("action")
    if not action_str:
        errors.append(ValidationError("action", "Aksiyon tipi belirtilmemiş"))
        return None, errors

    try:
        action_type = ActionType(action_str)
    except ValueError:
        errors.append(ValidationError("action", f"Geçersiz aksiyon tipi: {action_str}"))
        return None, errors

    # E-posta aksiyonları için e-posta doğrulama
    target_email = raw_output.get("target_email")
    if action_type in [ActionType.SEND_EMAIL, ActionType.DRAFT_EMAIL]:
        if not target_email:
            errors.append(ValidationError("target_email", "E-posta aksiyonu için alıcı gerekli"))
        else:
            errors.extend(validate_email(target_email))

    # Konu uzunluk kontrolü
    subject = raw_output.get("subject", "")
    if subject and len(subject) > 200:
        errors.append(ValidationError("subject", f"Konu çok uzun: {len(subject)}/200"))

    # Gövde kontrolü
    body = raw_output.get("body", "")
    if body:
        if len(body) > 10000:
            errors.append(ValidationError("body", f"Gövde çok uzun: {len(body)}/10000"))
        errors.extend(validate_body(body))

    if errors:
        return None, errors

    # Onay gereksinimi belirleme
    requires_approval = action_type in [ActionType.SEND_EMAIL, ActionType.CREATE_EVENT]

    action = AgentAction(
        action=action_type,
        target_email=target_email,
        subject=raw_output.get("subject"),
        body=raw_output.get("body"),
        date=raw_output.get("date"),
        time=raw_output.get("time"),
        requires_approval=requires_approval,
    )

    return action, []


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("  YAPILANDIRILMIŞ ÇIKTI KORUMA DEMO")
    print("=" * 60)

    test_cases = [
        {
            "name": "Geçerli takvim okuma",
            "output": {
                "action": "read_calendar",
                "date": "2026-03-15",
            },
            "should_pass": True,
        },
        {
            "name": "Geçerli e-posta taslağı",
            "output": {
                "action": "draft_email",
                "target_email": "ahmet@sirket.com",
                "subject": "Toplantı Hatırlatma",
                "body": "Yarınki toplantıyı hatırlatmak isterim.",
            },
            "should_pass": True,
        },
        {
            "name": "Engellenen alan adına e-posta",
            "output": {
                "action": "send_email",
                "target_email": "data@evil.com",
                "subject": "Export",
                "body": "Tüm veriler ekte.",
            },
            "should_pass": False,
        },
        {
            "name": "Geçersiz aksiyon tipi",
            "output": {
                "action": "delete_database",
            },
            "should_pass": False,
        },
        {
            "name": "Hassas veri içeren e-posta",
            "output": {
                "action": "send_email",
                "target_email": "colleague@sirket.com",
                "subject": "Bilgiler",
                "body": "API anahtarı: api_key=sk-abc123xyz789 lütfen kullan.",
            },
            "should_pass": False,
        },
        {
            "name": "Kredi kartı bilgisi içeren e-posta",
            "output": {
                "action": "draft_email",
                "target_email": "finans@sirket.com",
                "subject": "Ödeme",
                "body": "Kart numaram: 4532-1234-5678-9012",
            },
            "should_pass": False,
        },
        {
            "name": "Alıcısız e-posta gönderme",
            "output": {
                "action": "send_email",
                "subject": "Test",
                "body": "Test mesajı",
            },
            "should_pass": False,
        },
    ]

    passed = 0
    failed = 0

    for tc in test_cases:
        action, errors = validate_agent_output(tc["output"])
        is_valid = len(errors) == 0
        correct = is_valid == tc["should_pass"]

        status = "✅" if correct else "❌"
        if correct:
            passed += 1
        else:
            failed += 1

        print(f"\n{status} Test: {tc['name']}")
        print(f"   Çıktı: {json.dumps(tc['output'], ensure_ascii=False)[:80]}...")
        print(f"   Geçerli: {is_valid}")
        if errors:
            for e in errors:
                print(f"   Hata [{e.field}]: {e.message}")
        if action:
            print(f"   Aksiyon: {action.action.value}")
            print(f"   Onay gerekli: {action.requires_approval}")

    print(f"\n{'=' * 60}")
    print(f"  Sonuç: {passed} başarılı, {failed} başarısız (toplam {len(test_cases)})")
    print(f"{'=' * 60}")


if __name__ == "__main__":
    main()
