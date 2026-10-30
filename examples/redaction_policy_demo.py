"""
Maskeleme Politikası Demo
==========================
Bu demo, ajan çıktısındaki hassas verileri (PII, sırlar)
otomatik olarak tespit eden ve maskeleyen bir sistemi gösterir.

Çalıştırma:
    python examples/redaction_policy_demo.py
"""

import re
from dataclasses import dataclass
from enum import Enum


class DataSensitivity(str, Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


@dataclass
class RedactionPattern:
    """Maskeleme kalıbı tanımı."""
    name: str
    description: str
    pattern: str
    replacement: str
    sensitivity: DataSensitivity


@dataclass
class RedactionResult:
    """Maskeleme işleminin sonucu."""
    original_text: str
    redacted_text: str
    findings: list[dict]
    max_sensitivity: DataSensitivity


PII_PATTERNS = [
    RedactionPattern(
        name="tc_kimlik",
        description="TC Kimlik Numarası (11 haneli)",
        pattern=r"\b[1-9]\d{10}\b",
        replacement="[TC_KİMLİK_MASKELENDİ]",
        sensitivity=DataSensitivity.RESTRICTED,
    ),
    RedactionPattern(
        name="kredi_karti",
        description="Kredi kartı numarası (16 haneli)",
        pattern=r"\b\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}\b",
        replacement="[KREDİ_KARTI_MASKELENDİ]",
        sensitivity=DataSensitivity.RESTRICTED,
    ),
    RedactionPattern(
        name="e_posta",
        description="E-posta adresi",
        pattern=r"\b[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+\b",
        replacement="[E_POSTA_MASKELENDİ]",
        sensitivity=DataSensitivity.CONFIDENTIAL,
    ),
    RedactionPattern(
        name="telefon_tr",
        description="Türkiye telefon numarası",
        pattern=r"\b(?:\+90|0)\s?\d{3}\s?\d{3}\s?\d{2}\s?\d{2}\b",
        replacement="[TELEFON_MASKELENDİ]",
        sensitivity=DataSensitivity.CONFIDENTIAL,
    ),
    RedactionPattern(
        name="api_anahtari",
        description="API anahtarı veya token",
        pattern=r"(?i)(api[_-]?key|token|secret|password|passwd)\s*[:=]\s*['\"]?[\w\-\.]{8,}['\"]?",
        replacement="[API_ANAHTARI_MASKELENDİ]",
        sensitivity=DataSensitivity.RESTRICTED,
    ),
    RedactionPattern(
        name="iban",
        description="Uluslararası banka hesap numarası",
        pattern=r"\b[A-Z]{2}\d{2}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{4}\s?\d{2}\b",
        replacement="[IBAN_MASKELENDİ]",
        sensitivity=DataSensitivity.RESTRICTED,
    ),
    RedactionPattern(
        name="ip_adresi",
        description="IP adresi (v4)",
        pattern=r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
        replacement="[IP_MASKELENDİ]",
        sensitivity=DataSensitivity.INTERNAL,
    ),
]


def redact_sensitive_data(
    text: str,
    patterns: list[RedactionPattern] | None = None,
) -> RedactionResult:
    """Metindeki hassas verileri tespit eder ve maskeler."""
    if patterns is None:
        patterns = PII_PATTERNS

    findings = []
    redacted = text
    max_sensitivity = DataSensitivity.PUBLIC

    sensitivity_order = [
        DataSensitivity.PUBLIC,
        DataSensitivity.INTERNAL,
        DataSensitivity.CONFIDENTIAL,
        DataSensitivity.RESTRICTED,
    ]

    for rp in patterns:
        matches = re.findall(rp.pattern, redacted)
        if matches:
            match_count = len(matches) if isinstance(matches[0], str) else len(matches)
            findings.append({
                "type": rp.name,
                "description": rp.description,
                "count": match_count,
                "sensitivity": rp.sensitivity.value,
            })
            redacted = re.sub(rp.pattern, rp.replacement, redacted)

            if sensitivity_order.index(rp.sensitivity) > sensitivity_order.index(max_sensitivity):
                max_sensitivity = rp.sensitivity

    return RedactionResult(
        original_text=text,
        redacted_text=redacted,
        findings=findings,
        max_sensitivity=max_sensitivity,
    )


# ---------------------------------------------------------------------------
# Demo
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("  MASKELEME POLİTİKASI DEMO")
    print("=" * 60)

    test_cases = [
        {
            "name": "Güvenli metin",
            "text": "Yarın saat 14:00'te toplantımız var. Lütfen hazırlıklı gelin.",
        },
        {
            "name": "TC Kimlik numarası",
            "text": "Müşterinin TC kimlik numarası 12345678901 olarak kayıtlıdır.",
        },
        {
            "name": "Kredi kartı bilgisi",
            "text": "Ödeme için kart numarası: 4532-1234-5678-9012, son kullanma: 12/27",
        },
        {
            "name": "E-posta ve telefon",
            "text": "İletişim bilgileri: ahmet.yilmaz@sirket.com, +90 532 123 45 67",
        },
        {
            "name": "API anahtarı",
            "text": "Servis yapılandırması: api_key=sk-proj-abc123xyz789defghijklm, timeout=30",
        },
        {
            "name": "Çoklu hassas veri",
            "text": (
                "Kullanıcı raporu:\n"
                "Ad: Ahmet Yılmaz\n"
                "TC: 98765432109\n"
                "E-posta: ahmet@ornek.com\n"
                "Telefon: 0532 987 65 43\n"
                "Kart: 5412 7512 3412 3456\n"
                "Sunucu: 192.168.1.100\n"
                "API: token=bearer_xyz123abcdef456"
            ),
        },
        {
            "name": "IBAN numarası",
            "text": "Havale için IBAN: TR76 0001 0012 3456 7890 1234 56 hesabına gönderin.",
        },
    ]

    for tc in test_cases:
        result = redact_sensitive_data(tc["text"])
        icon = "🟢" if not result.findings else "🔴"

        print(f"\n{icon} Test: {tc['name']}")
        print(f"   Orijinal: {tc['text'][:100]}{'...' if len(tc['text']) > 100 else ''}")

        if result.findings:
            print(f"   Maskelenmiş: {result.redacted_text[:100]}{'...' if len(result.redacted_text) > 100 else ''}")
            print(f"   Maks hassasiyet: {result.max_sensitivity.value}")
            for f in result.findings:
                print(f"   Tespit: {f['description']} ({f['count']} adet, hassasiyet: {f['sensitivity']})")
        else:
            print("   Hassas veri tespit edilmedi ✓")

    # Egress politikası demo
    print(f"\n{'=' * 60}")
    print("  EGRESS POLİTİKASI DEMO")
    print(f"{'=' * 60}")

    email_body = (
        "Merhaba,\n\n"
        "Toplantı notlarını paylaşıyorum.\n"
        "Katılımcı: mehmet@sirket.com\n"
        "Telefon: +90 555 123 45 67\n\n"
        "Saygılarımla"
    )

    result = redact_sensitive_data(email_body)
    print(f"\n   Orijinal e-posta gövdesi:")
    for line in email_body.split("\n"):
        print(f"     {line}")

    print(f"\n   Maskelenmiş e-posta gövdesi:")
    for line in result.redacted_text.split("\n"):
        print(f"     {line}")

    if result.findings:
        print(f"\n   Tespit edilen hassas veriler:")
        for f in result.findings:
            print(f"     - {f['description']}: {f['count']} adet ({f['sensitivity']})")

    sensitivity_order = [
        DataSensitivity.PUBLIC,
        DataSensitivity.INTERNAL,
        DataSensitivity.CONFIDENTIAL,
        DataSensitivity.RESTRICTED,
    ]
    max_allowed = DataSensitivity.INTERNAL
    if sensitivity_order.index(result.max_sensitivity) > sensitivity_order.index(max_allowed):
        print(f"\n   ❌ Karar: E-posta GÖNDERİLEMEZ (hassasiyet: {result.max_sensitivity.value} > izin: {max_allowed.value})")
        print(f"   ℹ️  Öneri: Maskelenmiş versiyonu gönderin veya hassas verileri kaldırın")
    else:
        print(f"\n   ✅ Karar: E-posta gönderilebilir")


if __name__ == "__main__":
    main()
