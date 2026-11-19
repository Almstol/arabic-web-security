from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import dns.resolver
from sqlalchemy import select
from sqlalchemy.orm import selectinload

from .database import SessionLocal
from .models import Finding, Scan
from .scanner import fetch_headers, normalize_target

SEVERITY_WEIGHT = {"critical": 25, "high": 15, "medium": 8, "low": 3}


def _finding(code: str, severity: str, title: str, explanation: str, remediation: str, evidence=None):
    return {"code": code, "severity": severity, "title_ar": title,
            "explanation_ar": explanation, "remediation_ar": remediation,
            "status": "open", "evidence": evidence or {}}


def _dns_txt(name: str) -> list[str]:
    resolver = dns.resolver.Resolver(configure=True)
    resolver.timeout = 1.5
    resolver.lifetime = 2.0
    try:
        answers = resolver.resolve(name, "TXT")
        return [b"".join(record.strings).decode("utf-8", "replace") for record in answers]
    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.NoNameservers,
            dns.exception.Timeout, OSError):
        return []


def analyze_headers(host: str, origin: str, status: int, headers: dict[str, str]) -> list[dict]:
    findings = []
    checks = [
        ("content-security-policy", "header_csp", "medium", "سياسة أمان المحتوى غير موجودة",
         "لم تُرسل الاستجابة ترويسة CSP. تساعد السياسة المناسبة على تقييد مصادر المحتوى في المتصفح.",
         "ابدأ بسياسة Content-Security-Policy-Report-Only، راجع التقارير، ثم طبّق سياسة متوافقة مع موقعك."),
        ("x-content-type-options", "header_nosniff", "low", "ترويسة منع تخمين نوع المحتوى غير موجودة",
         "لم تُرسل ترويسة X-Content-Type-Options.", "أضف X-Content-Type-Options: nosniff إلى الاستجابات المناسبة."),
        ("referrer-policy", "header_referrer_policy", "low", "سياسة الإحالة غير محددة",
         "قد يرسل المتصفح معلومات إحالة أكثر من المطلوب عند الانتقال إلى مواقع أخرى.",
         "راجع سياسة الإحالة المطلوبة وأضف Referrer-Policy مثل strict-origin-when-cross-origin."),
        ("permissions-policy", "header_permissions_policy", "low", "سياسة أذونات المتصفح غير محددة",
         "لم تظهر ترويسة تحدد ميزات المتصفح المتاحة للصفحة.",
         "حدد ميزات المتصفح التي يحتاجها الموقع فقط باستخدام Permissions-Policy."),
    ]
    for header, code, severity, title, explanation, fix in checks:
        if not headers.get(header):
            findings.append(_finding(code, severity, title, explanation, fix, {"header": header}))
    if origin.startswith("https://") and not headers.get("strict-transport-security"):
        findings.append(_finding("header_hsts", "medium", "ترويسة HSTS غير موجودة",
            "لم تظهر Strict-Transport-Security في استجابة HTTPS.",
            "بعد التأكد من دعم HTTPS لكل النطاقات الفرعية، أضف HSTS بمدة مناسبة واختبر التغيير."))
    if status in {401, 403, 405}:
        findings.append(_finding("head_limited", "info", "الخادم يقيّد طلب HEAD",
            "لم يسمح الخادم بجمع الترويسات عبر طلب HEAD. قد تكون بعض المؤشرات غير متاحة.",
            "لا يلزم إجراء؛ هذه النتيجة تحد من دقة الفحص السلبي فقط.", {"status": status}))
    spf = [record for record in _dns_txt(host) if record.lower().startswith("v=spf1")]
    if not spf:
        findings.append(_finding("dns_spf", "medium", "لم يُعثر على سجل SPF",
            "لم يظهر سجل SPF في استجابة DNS. قد يؤثر ذلك على حماية البريد المرسل باسم النطاق.",
            "راجع مزود البريد لديك وأنشئ سجل SPF واحدًا يضم مصادر الإرسال المعتمدة."))
    dmarc = [record for record in _dns_txt("_dmarc." + host) if record.lower().startswith("v=dmarc1")]
    if not dmarc:
        findings.append(_finding("dns_dmarc", "medium", "لم يُعثر على سجل DMARC",
            "لم يظهر سجل DMARC في استجابة DNS. يساعد DMARC على تحديد سياسة التعامل مع رسائل النطاق المزورة.",
            "ابدأ بسياسة p=none مع عنوان تقارير صالح، ثم شدد السياسة بعد مراجعة التقارير."))
    return findings


def run_site_scan(scan_id: str) -> None:
    db = SessionLocal()
    try:
        scan = db.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "running"
        db.commit()
        origin, host = normalize_target("https://" + scan.target)
        status, headers = asyncio.run(fetch_headers(origin))
        findings = analyze_headers(host, origin, status, headers)

        previous = db.scalar(select(Scan).options(selectinload(Scan.findings)).where(
            Scan.target == host, Scan.status == "completed", Scan.id != scan.id
        ).order_by(Scan.created_at.desc()).limit(1))
        previous_codes = {item.code for item in previous.findings} if previous else set()
        historical_codes = set(db.scalars(select(Finding.code).join(Scan).where(
            Scan.target == host, Scan.status == "completed"
        )).all())
        current_codes = {item["code"] for item in findings}

        if previous:
            for old in previous.findings:
                if old.code not in current_codes:
                    old.status = "fixed"
            fixed_count = len(previous_codes - current_codes)
            new_count = len(current_codes - previous_codes)
            scan.summary = f"مقارنة بآخر فحص مكتمل: {fixed_count} نتيجة اختفت و{new_count} نتيجة جديدة ظهرت."
        for item in findings:
            if item["code"] not in previous_codes and item["code"] in historical_codes:
                item["status"] = "reopened"
            db.add(Finding(scan_id=scan.id, **item))

        scan.score = max(0, 100 - sum(SEVERITY_WEIGHT.get(item["severity"], 0) for item in findings))
        scan.status = "completed"
        scan.completed_at = datetime.now(timezone.utc)
        db.commit()
    except Exception:
        db.rollback()
        scan = db.get(Scan, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.summary = "تعذر إكمال الفحص. قد يكون النطاق غير متاح أو محميًا أو قد رفض الاتصال."
            scan.completed_at = datetime.now(timezone.utc)
            db.commit()
    finally:
        db.close()
