from contextlib import asynccontextmanager
import ipaddress
from urllib.parse import urlsplit
from uuid import UUID

from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.util import get_remote_address
from sqlalchemy import select
from sqlalchemy.orm import Session, selectinload

from .config import settings
from .database import Base, engine, get_db
from .models import Scan
from .scanner import UnsafeTarget, normalize_target
from .schemas import LinkAnalysisCreate, LinkAnalysisOut, LinkIndicator, ScanAccepted, ScanOut, SiteScanCreate
from .worker import scan_site_task

limiter = Limiter(key_func=get_remote_address, default_limits=[settings.scan_rate_limit])


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Prototype bootstrap. Use versioned Alembic migrations before production.
    Base.metadata.create_all(bind=engine)
    yield


app = FastAPI(title="درع | API", description="واجهة خدمات التحليل السلبي", version="0.1.0", lifespan=lifespan)
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(CORSMiddleware, allow_origins=settings.allowed_origins,
                   allow_credentials=False, allow_methods=["GET", "POST"],
                   allow_headers=["Content-Type"])


def public_host(url: str) -> str:
    try:
        _, host = normalize_target(url)
        return host
    except UnsafeTarget as exc:
        raise HTTPException(status_code=422, detail="أدخل نطاقًا عامًا صالحًا") from exc


@app.get("/health")
def health():
    return {"status": "ok", "service": "dera-api", "mode": "passive-prototype"}


@app.post("/api/scans/site", response_model=ScanAccepted, status_code=202)
@limiter.limit(settings.scan_rate_limit)
def create_site_scan(request: Request, payload: SiteScanCreate, db: Session = Depends(get_db)):
    try:
        _, host = normalize_target(payload.url)
    except UnsafeTarget as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    scan = Scan(target=host, kind="site", status="queued")
    db.add(scan)
    db.commit()
    db.refresh(scan)
    try:
        scan_site_task.delay(str(scan.id))
    except Exception as exc:
        scan.status = "failed"
        scan.summary = "تعذر وضع المهمة في قائمة الانتظار. تحقق من خدمة العامل."
        db.commit()
        raise HTTPException(status_code=503, detail="خدمة الفحص غير متاحة مؤقتًا") from exc
    return ScanAccepted(scan_id=scan.id, status=scan.status,
                        message_ar="أُضيف الفحص السلبي إلى قائمة الانتظار. لا تُجرى اختبارات نشطة.")


@app.get("/api/scans/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: UUID, db: Session = Depends(get_db)):
    scan = db.scalar(select(Scan).options(selectinload(Scan.findings)).where(Scan.id == scan_id))
    if scan is None:
        raise HTTPException(status_code=404, detail="لم يُعثر على الفحص")
    return scan


@app.get("/api/domains/{domain}/history", response_model=list[ScanOut])
def domain_history(domain: str, db: Session = Depends(get_db)):
    host = public_host("https://" + domain)
    scans = db.scalars(select(Scan).options(selectinload(Scan.findings)).where(
        Scan.target == host, Scan.status.in_(["completed", "failed"])
    ).order_by(Scan.created_at.desc()).limit(50)).all()
    return scans


@app.post("/api/links/analyze", response_model=LinkAnalysisOut)
@limiter.limit(settings.scan_rate_limit)
def analyze_link(request: Request, payload: LinkAnalysisCreate):
    """Offline shape-only check: this endpoint never fetches or resolves the supplied URL."""
    try:
        parsed = urlsplit(payload.url.strip())
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname:
            raise ValueError
        if parsed.username is not None or parsed.password is not None:
            raise ValueError
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        port = parsed.port
    except (ValueError, UnicodeError) as exc:
        raise HTTPException(status_code=422, detail="أدخل رابط HTTP(S) صالحًا") from exc
    indicators = []

    def add(code, severity, title, explanation):
        indicators.append(LinkIndicator(code=code, severity=severity, title_ar=title, explanation_ar=explanation))

    try:
        ipaddress.ip_address(host)
        add("ip_host", "high", "الرابط يستخدم عنوان IP مباشرًا", "تحقق من الجهة عبر قناة مستقلة ولا تدخل بياناتك في صفحة غير متوقعة.")
    except ValueError:
        pass
    if "@" in payload.url:
        add("at_symbol", "high", "يحتوي الرابط على علامة @", "قد تجعل العلامة الوجهة الفعلية أقل وضوحًا؛ افحص اسم النطاق بعناية.")
    if host.startswith("xn--") or ".xn--" in host:
        add("punycode", "medium", "اسم النطاق يستخدم ترميزًا دوليًا", "قد تتشابه بعض الحروف بصريًا؛ تحقق من النطاق حرفًا بحرف.")
    if len(host.split(".")) > 4:
        add("many_subdomains", "medium", "يحتوي النطاق على مستويات فرعية كثيرة", "تأكد من النطاق الأساسي المقصود عبر الموقع الرسمي للجهة.")
    if port not in (None, 80, 443):
        add("unusual_port", "low", "الرابط يستخدم منفذًا غير شائع", "تحقق من سبب استخدام هذا المنفذ قبل المتابعة.")
    risk = min(95, sum({"high": 35, "medium": 18, "low": 10}.get(item.severity, 0) for item in indicators))
    verdict = "suspicious" if risk >= 30 else "no_obvious_signs"
    message = "تجنب فتح الرابط أو إدخال معلومات شخصية." if risk >= 30 else "لم تظهر مؤشرات شكلية بارزة، لكن ذلك لا يثبت سلامة الرابط."
    return LinkAnalysisOut(verdict=verdict, risk_score=risk, message_ar=message,
        indicators=indicators, limitation_ar="تحليل شكلي محلي فقط؛ لا يجري DNS أو HTTP أو سمعة أو تصويرًا للصفحة، ولا يؤكد أن الرابط آمن.")
