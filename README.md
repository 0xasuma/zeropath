# 🛡️ ZeroPath

**Autonomous Exploit Chain Generator** — Telegram Mini App

AI-powered security scanner yang mendeteksi vulnerability, menghasilkan attack chain otomatis, dan membuat PoC code + mitigation.

## ✨ Features

- 🔍 **Vulnerability Scanning** — XSS, SQLi, CORS, Headers, Info Disclosure
- 🤖 **AI Attack Chains** — Auto-generate exploit chains from multiple vulnerabilities
- 📝 **PoC Generation** — Working proof-of-concept code for each finding
- 📊 **Real-time Progress** — WebSocket updates during scan
- 📱 **Telegram Mini App** — Scan langsung dari Telegram, no install needed

## 🚀 Tech Stack

| Component | Tech |
|-----------|------|
| Frontend | HTML5 + Telegram WebApp SDK |
| Backend | Python FastAPI |
| Scanner | Custom engine (XSS, SQLi, CORS, Headers) |
| AI | Rule-based exploit chain correlation |
| Deployment | Cloudflare Tunnel + systemd |

## 📱 Telegram Bot

Bot: [@zeropath_scanner_bot](https://t.me/zeropath_scanner_bot)

### Commands
- `/start` — Launch Mini App
- `/help` — Show help

## 🏗️ Architecture

```
zeropath/
├── backend/
│   ├── main.py          # FastAPI server + WebSocket
│   ├── scanner.py       # Vulnerability scanner engine
│   ├── chain_ai.py      # Exploit chain AI logic
│   └── reporter.py      # HTML report generator
├── frontend/
│   └── index.html       # Telegram Mini App
├── reports/             # Generated scan reports
├── bot.py               # Telegram bot launcher
├── requirements.txt
└── deploy.sh
```

## 🔧 Self-Host

1. Clone repo
2. Install deps: `pip install -r requirements.txt`
3. Run backend: `cd backend && python main.py`
4. Run bot: `python bot.py`
5. Set Telegram menu button URL to your domain

## 📊 Scan Results Include

- Vulnerabilities with severity (Critical/High/Medium/Low/Info)
- CWE references
- Evidence for each finding
- Auto-generated attack chains
- Step-by-step exploitation path
- PoC code
- Mitigation recommendations

## 🔐 Security

ZeroPath is designed for **authorized security testing only**. Always get permission before scanning any target.

## 📄 License

MIT

---

Built with ❤️ by [0xasuma](https://github.com/0xasuma)
