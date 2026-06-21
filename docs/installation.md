# Installation

Requires Python 3.11+. Tested in CI on Windows, Ubuntu, and macOS (see
`.github/workflows/ci.yml`); the same instructions apply to Kali and Linux
Mint since they're Debian/Ubuntu-based.

## Windows (PowerShell)

```powershell
git clone <your-fork-url> websec-assess
cd websec-assess
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"
websec-assess plugins
```

## Ubuntu / Debian / Kali / Linux Mint

```bash
git clone <your-fork-url> websec-assess
cd websec-assess
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
websec-assess plugins
```

Kali ships Python 3 by default. On a minimal Ubuntu/Debian/Mint install, you
may need `sudo apt install python3-venv` first.

## Docker (any OS)

```bash
docker compose build
docker compose run --rm websec-assess init --target example.com
docker compose run --rm websec-assess scan https://example.com --i-have-authorization
```

Reports land in `./reports` and the SQLite DB / audit log in `./data` (both
volume-mounted from `docker-compose.yml`).

## Optional external tools

The `integrations.*` plugins (nuclei, katana, httpx, subfinder, dnsx,
naabu, gau, waybackurls) are no-ops if the binary isn't on `PATH` --
`websec-assess plugins` still lists them, they just produce no findings.
Install whichever you want via ProjectDiscovery's installer or `go install`:

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/tomnomnom/waybackurls@latest
```

These install to `$GOPATH/bin` (`%USERPROFILE%\go\bin` on Windows) -- make
sure that's on `PATH`. Kali's repos also package several of these directly
(`sudo apt install nuclei seclists`, etc.).

If a binary lives somewhere non-standard, point `tool_paths.<name>` at the
full path in your config instead of relying on `PATH`.

## PostgreSQL instead of SQLite

```bash
pip install -e ".[postgres]"
```

```yaml
database:
  url: postgresql://websec:websec@localhost:5432/websec_assess
```

`docker compose --profile postgres up -d postgres` starts a local Postgres
matching those credentials.
