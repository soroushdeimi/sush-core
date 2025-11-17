# راهنمای Linting و کیفیت کد - sush-core

## مشکل اصلی

در پروژه‌های Python با optional dependencies (مثل `aioquic`، `scapy`)، ممکن است importهایی وجود داشته باشند که فقط برای بررسی availability استفاده می‌شوند و سپس استفاده نمی‌شوند.

## راه حل‌های پیشنهادی

### 1. حذف Importهای استفاده نشده (بهترین روش)

اگر import واقعاً استفاده نمی‌شود، باید حذف شود:

```python
# ❌ بد
try:
    import aioquic  # استفاده نمی‌شود
    from aioquic.asyncio import connect as quic_connect
    QUIC_AVAILABLE = True
except ImportError:
    QUIC_AVAILABLE = False

# ✅ خوب
try:
    from aioquic.asyncio import connect as quic_connect
    QUIC_AVAILABLE = True
except ImportError:
    QUIC_AVAILABLE = False
    quic_connect = None
```

### 2. استفاده از importlib.util.find_spec (برای بررسی availability)

اگر فقط می‌خواهید بررسی کنید که یک ماژول موجود است:

```python
import importlib.util

if importlib.util.find_spec("aioquic") is not None:
    from aioquic.asyncio import connect as quic_connect
    QUIC_AVAILABLE = True
else:
    QUIC_AVAILABLE = False
    quic_connect = None
```

### 3. استفاده از per-file-ignores در ruff.toml

اگر import واقعاً لازم است اما ruff آن را تشخیص نمی‌دهد:

```toml
[lint.per-file-ignores]
"sush/transport/protocol_hopper.py" = ["F401"]
```

**توجه**: این روش باید فقط در موارد خاص استفاده شود.

## دستورالعمل‌های پروژه

1. **همیشه importهای استفاده نشده را حذف کنید**
2. **برای optional dependencies از try/except استفاده کنید**
3. **متغیرهای import شده را در except block مقداردهی کنید**
4. **قبل از استفاده از متغیرها، availability را بررسی کنید**

## مثال کامل

```python
# Import libraries for QUIC support
try:
    from aioquic.asyncio import connect as quic_connect
    from aioquic.quic.configuration import QuicConfiguration
    QUIC_AVAILABLE = True
except ImportError:
    QUIC_AVAILABLE = False
    quic_connect = None
    QuicConfiguration = None
    logger.debug("aioquic not available; QUIC protocol will fall back to TCP.")

# استفاده
if QUIC_AVAILABLE and quic_connect:
    connection = await quic_connect(...)
```

## بررسی منظم

برای اطمینان از کیفیت کد:

```bash
# بررسی linting
python -m ruff check sush data

# رفع خودکار
python -m ruff check sush data --fix

# رفع با unsafe fixes
python -m ruff check sush data --unsafe-fixes --fix
```

## نکات مهم

1. **Cache را پاک کنید** قبل از بررسی linting:
   ```powershell
   Get-ChildItem -Path . -Include __pycache__,*.pyc -Recurse -Force | Remove-Item -Recurse -Force
   ```

2. **همیشه بعد از تغییرات linting را بررسی کنید**

3. **از CI/CD برای بررسی خودکار استفاده کنید**

