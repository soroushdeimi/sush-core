# راهنمای اجرای بنچمارک‌ها

## وضعیت فعلی

اسکریپت‌های بنچمارک آماده هستند و شامل:

1. **`run_benchmarks.py`** - اسکریپت اصلی بنچمارک (3 آزمایش)
2. **`analyze_results.py`** - تحلیل و مصورسازی نتایج
3. **`run_benchmarks_direct.py`** - نسخه با logging مستقیم به فایل
4. **`test_benchmark_simple.py`** - تست ساده برای بررسی عملکرد

## نحوه اجرا

### روش 1: اجرای مستقیم

```bash
# اجرای بنچمارک‌ها
python tests/run_benchmarks.py

# یا با logging مستقیم
python tests/run_benchmarks_direct.py
```

### روش 2: اجرای تست ساده

```bash
# تست سریع (فقط Experiment A)
python tests/test_benchmark_simple.py
```

### روش 3: تحلیل نتایج

```bash
# بعد از اجرای بنچمارک‌ها
python tests/analyze_results.py
```

## پورت‌های استفاده شده

- **پورت‌های امن**: 54321, 55555, 60000, 61000 (ephemeral range)
- **آدرس**: 127.0.0.1 (فقط localhost)
- **هدف**: جلوگیری از بسته شدن توسط فایروال/ISP

## فایل‌های خروجی

بعد از اجرای موفق، فایل‌های زیر ایجاد می‌شوند:

```
tests/data/
├── benchmark_results.csv      # داده‌های خام
├── benchmark_run.log          # لاگ اجرا
└── plots/
    ├── crypto_overhead.png
    ├── throughput_comparison.png
    └── reaction_time.png
```

## آزمایش‌های انجام شده

### Experiment A: Crypto Overhead
- اندازه‌گیری زمان obfuscate/deobfuscate
- Payload sizes: 1KB, 10KB, 100KB, 1MB
- 50 تکرار برای هر اندازه

### Experiment B: End-to-End Throughput
- تست با SushServer و SushClient واقعی
- مقایسه DIRECT vs STEGANOGRAPHIC modes
- انتقال 10MB داده

### Experiment C: Adaptive Response Time
- اندازه‌گیری زمان پاسخ AdaptiveControlLoop
- تزریق metrics حمله و اندازه‌گیری reaction time

## عیب‌یابی

اگر خروجی نمایش داده نمی‌شود:

1. بررسی کنید که Python در PATH است
2. بررسی کنید که تمام dependencies نصب شده‌اند:
   ```bash
   pip install -r requirements.txt
   ```
3. اجرا با verbose output:
   ```bash
   python -u tests/run_benchmarks.py 2>&1 | tee output.log
   ```
4. بررسی فایل لاگ:
   ```bash
   cat tests/data/benchmark_run.log
   ```

## نکات مهم

- تمام تست‌ها روی **localhost** اجرا می‌شوند (127.0.0.1)
- هیچ اتصال خارجی ایجاد نمی‌شود
- پورت‌های ephemeral استفاده می‌شوند (امن برای تست)
- در صورت اشغال بودن پورت، پورت بعدی امتحان می‌شود

## زمان تقریبی اجرا

- Experiment A: ~2-5 دقیقه (50 تکرار × 4 اندازه)
- Experiment B: ~1-2 دقیقه (2 mode × 10MB)
- Experiment C: ~30-60 ثانیه (simulation)

**کل زمان**: حدود 5-10 دقیقه

