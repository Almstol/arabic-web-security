# درع — منصة عربية لأمان الويب

واجهة MVP عربية RTL وخلفية أولية للفحص السلبي وتحليل شكل الروابط.

## تشغيل الواجهة التجريبية

افتح `index.html` مباشرة أو شغّل خادم ملفات ثابتة:

```bash
python -m http.server 8000
```

## تشغيل API والخدمات محليًا

المتطلبات: Docker وDocker Compose.

```bash
cp .env.example .env
# غيّر POSTGRES_PASSWORD إلى قيمة عشوائية قوية، واجعل كلمة المرور في DATABASE_URL مطابقة لها.
docker compose up --build
```

- API: `http://localhost:8000`
- توثيق OpenAPI: `http://localhost:8000/docs`
- فحص الصحة: `http://localhost:8000/health`

### أمثلة API

```bash
curl -X POST http://localhost:8000/api/scans/site \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com"}'

curl http://localhost:8000/api/scans/SCAN_UUID
curl -X POST http://localhost:8000/api/links/analyze \
  -H 'Content-Type: application/json' \
  -d '{"url":"https://example.com/login"}'
curl http://localhost:8000/api/domains/example.com/history
```

## ما تنفذه الخلفية الحالية؟

- FastAPI API مع فحص صحة الخدمة وOpenAPI.
- مهمة Celery/Redis منفصلة لفحص الموقع السلبي، وPostgreSQL لحفظ سجل الفحوصات والنتائج.
- يجمع الفحص ترويسات الاستجابة عبر طلب `HEAD` واحد، دون متابعة التحويلات أو قراءة جسم الصفحة، ويفحص وجود SPF وDMARC عبر DNS.
- يرفض النطاقات المحلية وعناوين IP المباشرة والمنافذ المخصصة، ويتحقق محلل الاتصال من أن عناوين DNS عامة قبل الاتصال.
- يقارن النتائج مع آخر فحص مكتمل ويحدد النتائج المختفية أو التي ظهرت من جديد.
- تحليل الروابط محلي شكلي فقط: لا يفتح الرابط ولا يجري DNS أو اتصالات خارجية.
- حد معدل افتراضي 10 طلبات في الدقيقة لكل عنوان IP.

## حدود الأمان والنطاق

هذه خلفية أولية وليست جاهزة للإنتاج. لا توجد حاليًا مصادقة أو حسابات أو إثبات ملكية النطاق أو جدولة/تنبيهات أو PDF أو واجهة frontend متصلة بالـAPI. لا يوجد فحص نشط أو استكشاف منافذ أو مسارات أو CVE أو تصوير صفحات. يجب أن يقتصر الاستخدام على النطاقات التي تملكها أو لديك إذن بفحصها.

قبل الإنتاج: إضافة Alembic migrations، مصادقة وتفويض، إثبات الملكية وسياسات الاحتفاظ، اختبارات أمنية وتكاملية، مراقبة وتنبيهات، TLS أمام Caddy، ومراجعة SSRF وحدود الشبكة. لا تستخدم `.env.example` كما هو في الإنتاج.
