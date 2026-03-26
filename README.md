# 📱 Mobile Security Agent v1.2

**APK & IPA аюулгүй байдлын шинжилгээний хэрэгсэл — Gemini CLI дэмжлэгтэй**

Play Store / App Store URL эсвэл локал APK/IPA файлаас автоматаар аюулгүй байдлын дутагдлуудыг илрүүлж, Gemini AI-аар дүн шинжилгээ хийж, тайлан гаргадаг.

---

## 🔧 Суулгах (Installation)

### 1. Репозитори татах

```bash
git clone https://github.com/Tsoomoo0106/app_scan_agent
cd app_scan_agent
```

### 2. Бүтцийг засах + хэрэгслүүд суулгах

```bash
bash setup.sh
```

`setup.sh` нь дараах зүйлсийг автоматаар хийнэ:
- `scripts/` package үүсгэх ба модулиудыг зөв байрлалд оруулах
- `jadx` (APK decompiler) суулгах
- `apktool` (resource extractor) суулгах
- `ripgrep` (хурдан хайлт) суулгах
- `apkeep` (APK татагч) суулгах
- Python dependency суулгах

### 3. Gemini CLI суулгах (AI Agent)

```bash
# Node.js хэрэгтэй (v18+)
# Linux (Debian/Ubuntu/Kali):
curl -fsSL https://deb.nodesource.com/setup_20.x | sudo bash -
sudo apt-get install -y nodejs

# macOS:
brew install node

# Gemini CLI суулгах
npm install -g @google/gemini-cli

# Google account-ээр нэг удаа нэвтрэх
gemini
```

### 4. AI backend шалгах

```bash
python3 msa.py ai-info
```

Гаралт:
```
🤖 AI Backend Detection
========================================
  Active             : gemini
  gemini CLI         : ✅
  claude CLI         : ❌  https://claude.ai/code
  GEMINI_API_KEY     : ❌ not set
  ANTHROPIC_API_KEY  : ❌ not set
```

---

## ▶️ Ажиллуулах (Usage)

### Бүрэн скан (Play Store URL)

```bash
python3 msa.py scan "https://play.google.com/store/apps/details?id=com.example.app"
```

### Бүрэн скан (локал APK)

```bash
python3 msa.py scan myapp.apk
```

### AI-гүй хурдан скан

```bash
python3 msa.py scan myapp.apk --no-ai
```

### Зөвхөн нууц мэдээлэл хайх

```bash
python3 msa.py secrets output/com.example.app/decompiled/
```

### Permission шинжилгээ

```bash
python3 msa.py permissions output/com.example.app/resources/AndroidManifest.xml
```

### Тодорхой файл AI-ээр шинжлэх

```bash
python3 msa.py review output/com.example.app/decompiled/com/example/NetworkClient.java
```

---

## 📊 Илрүүлдэг зүйлс

| Модуль | Илрүүлдэг зүйл |
|--------|----------------|
| 🔑 **Secrets** | API key, AWS key, JWT, private key, Firebase key |
| 🔒 **SSL/TLS** | Certificate bypass, trust-all certs, WebView SSL алдаа |
| 🔐 **Crypto** | MD5, AES-ECB, hardcoded IV, insecure Random |
| 🌐 **WebView** | JS enabled, JS bridge, file access |
| 💾 **Storage** | World-readable файл, external storage, log leak |
| 📋 **Permissions** | Аюултай permission, spyware combo |
| 💉 **SQLi** | rawQuery/execSQL string concat |
| 🧠 **AI Review** | Gemini-ийн гүнзгий дүн шинжилгээ |

---

## 📁 Гаралтын бүтэц

```
output/
└── com.example.app/
    ├── decompiled/          ← jadx Java/Kotlin source
    ├── resources/           ← apktool manifest + resources
    ├── raw/                 ← Raw APK contents
    ├── framework.txt        ← Detected framework
    ├── jadx.log
    ├── findings/
    │   ├── secrets.txt
    │   ├── ssl.txt
    │   ├── crypto.txt
    │   ├── webview.txt
    │   ├── storage.txt
    │   ├── permissions.txt
    │   ├── sqli.txt
    │   └── ai_code_review.txt
    └── report.md            ← Эцсийн тайлан
```

---

## 🤖 AI Backend дэмжлэг

| Эрэмбэ | Backend | Тохиргоо |
|--------|---------|----------|
| 1 | **Gemini CLI** (санал болгосон) | `npm install -g @google/gemini-cli` → `gemini` |
| 2 | Claude CLI | Claude Code суулгасан бол автоматаар |
| 3 | Gemini API | `export GEMINI_API_KEY=your_key` |
| 4 | Anthropic API | `export ANTHROPIC_API_KEY=your_key` |

---

## ⚠️ Хариуцлагатай хэрэглээ

Энэ хэрэгслийг зөвхөн **зөвшөөрөлтэй** аюулгүй байдлын судалгаанд ашиглана уу:

- ✅ Өөрийн эсвэл зөвшөөрөл авсан апп
- ✅ Bug bounty program
- ✅ CTF challenge
- ✅ Хариуцлагатай мэдээлэл задруулалттай судалгаа

Зөвшөөрөлгүйгээр бусдын аппыг халдлагад өртүүлэхийг **хориглоно**.

---

## License

Apache-2.0
