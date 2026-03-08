# Installation

## Requirements

| Requirement | Version |
|-------------|---------|
| Python | 3.10 or later |
| pip | Latest recommended |
| OS | Linux, macOS, Windows 10+ |

---

## Standard Installation

```bash
git clone https://github.com/your-org/plasma.git
cd plasma

python -m venv venv

# Linux / macOS
source venv/bin/activate

# Windows (Command Prompt)
venv\\Scripts\\activate.bat

# Windows (PowerShell)
venv\\Scripts\\Activate.ps1

pip install -r requirements.txt
pip install -e .
```

After installation, you can run Plasma from anywhere using the `plasma` command instead of `python main.py`.

```bash
plasma --help
```

---

## Core Dependencies

| Package | Purpose |
|---------|---------|
| `requests` | HTTP client |
| `urllib3` | Connection pooling |
| `flask` + `flask-cors` | Web dashboard |
| `beautifulsoup4` + `lxml` | HTML parsing and crawling |
| `markdown` | Markdown report rendering |
| `pyyaml` | Nuclei-style template support |
| `rich` | Terminal output formatting |
| `pyfiglet` | ASCII banner |

---

## Optional Dependencies

### PDF Reports (`weasyprint`)

WeasyPrint requires system-level graphics libraries.

**Linux (Debian/Ubuntu):**
```bash
sudo apt-get install python3-cffi libcairo2 libpango-1.0-0 libpangocairo-1.0-0 libgdk-pixbuf2.0-0
pip install weasyprint
```

**macOS (Homebrew):**
```bash
brew install pango gdk-pixbuf libffi
pip install weasyprint
```

**Windows:**
WeasyPrint on Windows requires GTK. Install [GTK3 for Windows](https://github.com/tschoonj/GTK-for-Windows-Runtime-Environment-Installer/releases) first.

---

### Browser-Mode Crawling (`playwright`)

Required for the `--browser` flag on JavaScript-heavy and single-page applications.

```bash
pip install playwright
playwright install chromium
```

Playwright downloads a bundled Chromium binary (~150 MB). No system Chrome installation is required.

---

### HTTP/2 Support (`httpx`)

Required for the `--http2` flag.

```bash
pip install httpx[http2]
```

---

### WebSocket Fuzzing (`websockets`)

Required for the `--fuzz-websocket` flag.

```bash
pip install websockets
```

---

### Subdomain Takeover DNS Resolution (`dnspython`)

Required for CNAME resolution in `--subdomain-takeover`.

```bash
pip install dnspython
```

---

## Verifying the Installation

```bash
# Print the help message
plasma --help

# Confirm all core detectors load
python -c "from core.detector_registry import DetectorRegistry; r = DetectorRegistry(); r.load_all(); print(f'{len(r)} detectors loaded')"
```

---

## Troubleshooting

**`ModuleNotFoundError: No module named 'rich'`**
Run `pip install -r requirements.txt` inside your virtual environment.

**`ImportError` for `weasyprint`**
Install the system graphics libraries listed above before running `pip install weasyprint`.

**`playwright._impl._errors.Error: Executable doesn't exist`**
Run `playwright install chromium` after installing the Python package.

**`plasma` command not found**
Ensure you have run `pip install -e .` and that your virtual environment is activated.

**Permission denied on Linux/macOS**
Do not use `sudo pip`. Use a virtual environment as described above.

**Windows `Activate.ps1` blocked by execution policy**
Run: `Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser`
