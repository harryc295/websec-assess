FROM python:3.12-slim AS base

# Authorised-use-only platform -- see SECURITY.md. This image ships the
# Python tool itself; the optional external scanners (nuclei, katana, httpx,
# subfinder, dnsx, naabu, gau, waybackurls) are NOT bundled -- install them
# in a derived image or mount them from the host if you need those plugins.

WORKDIR /app

COPY pyproject.toml SECURITY.md README.md LICENSE ./
COPY src ./src

RUN pip install --no-cache-dir .

RUN useradd --create-home --uid 1000 wsa
USER wsa
WORKDIR /home/wsa

VOLUME ["/home/wsa/data"]

ENTRYPOINT ["websec-assess"]
CMD ["--help"]
