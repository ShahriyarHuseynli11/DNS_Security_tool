# 🔐 DNS Security — DNS Security Analysis Tool

A lightweight web app built with Python (Flask) for quickly analyzing a domain's DNS setup. Enter a domain and it fetches DNS records, checks DNSSEC, cross-checks responses across multiple DNS servers to flag possible spoofing, and looks up DANE/TLSA records.

## ✨ Key features

- **DNS lookup** — supports A, AAAA, MX, CNAME, NS, TXT, SOA, and PTR record types, with results cached in memory to speed up repeated queries.
- **DNSSEC check** — retrieves the domain's DNSKEY records and attempts to validate the RRSIG signature.
- **DNS spoofing analysis** — sends the same query in parallel to 3 different public DNS resolvers (Google `8.8.8.8`, Cloudflare `1.1.1.1`, Quad9 `9.9.9.9`); if the responses differ, it warns of a possible spoofing/cache-poisoning risk.
- **DANE / TLSA lookup** — checks for TLSA records under `_443._tcp.<domain>` to see whether the domain publishes extra TLS certificate validation via DNS.
- **Friendly UI** — Bootstrap 5 design, dark mode toggle, click-to-copy on results, and a loading spinner during requests.

## 🛠️ Tech stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| DNS handling | dnspython |
| Frontend | HTML, CSS, JavaScript, Bootstrap 5 |

## 📁 Project structure

```
├── app.py                 # Flask backend — all DNS/DNSSEC/spoofing logic
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html         # Main page
└── static/
    ├── css/style.css      # Styling and dark mode
    └── js/script.js       # Spinner, dark mode, clipboard functionality
```

## ⚙️ Setup

```bash
git clone <this-repo-url>
cd <repo-folder>

python -m venv venv
source venv/bin/activate      # Windows: venv\Scripts\activate

pip install -r requirements.txt
python app.py
```

Once running, open your browser at: **http://127.0.0.1:5000**

## 🚀 Usage

1. Enter a domain name (e.g. `google.com`)
2. Select a record type (A, AAAA, MX, etc.)
3. Click **"Sorğu Göndər"** (Submit Query)
4. Review the results: DNS answers, DNSSEC status, spoofing analysis, and DANE records

## ⚠️ Notes

- Requires an active internet connection — queries are sent directly to public DNS resolvers over UDP port 53.
- This is an educational/analysis tool, not a replacement for a professional security audit.
- The `venv/` folder is excluded via `.gitignore` and should never be committed.
