# A preview of the Power NetView console. See deploy/demo/app.py for what this
# is and, more importantly, what it is not — it runs the real server and the
# real bundle over an in-memory estate, with no TLS terminator in front of it.
#
#   docker build -f deploy/demo/Dockerfile -t power-netview-demo .
#   docker run --rm -p 8080:8080 \
#     -e POWERNETVIEW_BOOTSTRAP_USER=operator \
#     -e POWERNETVIEW_BOOTSTRAP_PASSWORD='choose something' \
#     power-netview-demo

# ── the console is BUILT here, not copied from a developer's machine ────────
# A `dist/` shipped from a laptop is a bundle nobody can reproduce, and it is
# gitignored anyway, so an image built from a clean checkout would silently have
# no console at all.
FROM node:20-alpine AS console
WORKDIR /console
COPY console/package.json console/package-lock.json ./
RUN npm ci
COPY console/tsconfig.json ./
COPY console/src ./src
RUN npx tsc

# ── the server ─────────────────────────────────────────────────────────────
FROM python:3.12-slim

# cryptography ships manylinux wheels, so no build toolchain is needed. openssl
# is here for the collector-side enrolment flow, not for the console.
RUN apt-get update \
 && apt-get install -y --no-install-recommends openssl \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /app

COPY ot_server/requirements.txt ./ot_server/requirements.txt
RUN pip install --no-cache-dir -r ot_server/requirements.txt

COPY ot_server ./ot_server
COPY ot_scanner ./ot_scanner
COPY console/public ./console/public
COPY deploy/demo ./deploy/demo
COPY --from=console /console/dist ./console/dist

# The CA is generated on first start and lives here. A named volume keeps the
# fleet's certificates verifiable across restarts; without one, every restart
# issues a new CA and orphans what came before — which is fine for a preview and
# would not be for a plant.
RUN mkdir -p /var/lib/power-netview/ca
VOLUME ["/var/lib/power-netview"]

EXPOSE 8080
ENV PORT=8080 PYTHONUNBUFFERED=1

# Not root. This holds a CA private key.
RUN useradd --system --uid 10001 netview \
 && chown -R netview:netview /var/lib/power-netview
USER netview

CMD ["python", "deploy/demo/app.py"]
