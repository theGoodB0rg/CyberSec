# syntax=docker/dockerfile:1

FROM node:20-bookworm-slim AS client-builder
WORKDIR /app
ENV PUPPETEER_SKIP_DOWNLOAD=true

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    make \
    g++ \
    bzip2 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
COPY client/package*.json client/

# Install dependencies with SSL workaround
# Disable SSL verification for npm and node-gyp (workaround for SSL issues in Docker builds)
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
RUN npm config set strict-ssl false && \
    npm cache clean --force && \
    (npm install || npm install --legacy-peer-deps || true) && \
    (npm --prefix client install || npm --prefix client install --legacy-peer-deps || true) && \
    # Verify critical dependencies are installed
    test -f client/node_modules/.bin/tsc || (echo "Client TypeScript not installed, retrying..." && npm --prefix client install typescript@latest && test -f client/node_modules/.bin/tsc) && \
    test -f client/node_modules/.bin/vite || (echo "Client Vite not installed, retrying..." && npm --prefix client install vite@latest && test -f client/node_modules/.bin/vite)
# Reset NODE_TLS_REJECT_UNAUTHORIZED for security
ENV NODE_TLS_REJECT_UNAUTHORIZED=1

COPY . .
RUN npm run client:build

FROM node:20-bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 python3-pip git \
      chromium \
      sqlite3 \
      bzip2 \
      ca-certificates \
      libnss3 libatk1.0-0 libx11-xcb1 libxcomposite1 libxcursor1 \
      libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libgbm1 \
      libasound2 libpangocairo-1.0-0 libgtk-3-0 libatk-bridge2.0-0 \
      libatspi2.0-0 libxrender1 libpango-1.0-0 libpangoft2-1.0-0 \
      libfontconfig1 libfreetype6 fonts-liberation \
    && git clone --depth=1 https://github.com/sqlmapproject/sqlmap.git /opt/sqlmap \
    && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmap.py "$@"\n' > /usr/local/bin/sqlmap \
    && printf '#!/bin/sh\nexec python3 /opt/sqlmap/sqlmapapi.py "$@"\n' > /usr/local/bin/sqlmapapi \
    && chmod +x /usr/local/bin/sqlmap /usr/local/bin/sqlmapapi \
    && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
    SQLMAP_PATH=/usr/local/bin/sqlmap \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    PUPPETEER_SKIP_DOWNLOAD=true \
    PORT=3001

COPY package*.json ./

# Install production dependencies with SSL workaround
ENV NODE_TLS_REJECT_UNAUTHORIZED=0
RUN npm config set strict-ssl false && \
    npm cache clean --force && \
    (npm install --omit=dev || npm install --omit=dev --legacy-peer-deps || true) && \
    # Verify core production dependencies are present
    test -d node_modules/express || (echo "Production dependencies not installed properly, retrying..." && npm install express && test -d node_modules/express)
# Reset NODE_TLS_REJECT_UNAUTHORIZED for security
ENV NODE_TLS_REJECT_UNAUTHORIZED=1

COPY --from=client-builder /app/server ./server
COPY --from=client-builder /app/client/dist ./client/dist
COPY --from=client-builder /app/scripts ./scripts
COPY --from=client-builder /app/docs ./docs

EXPOSE 3001
CMD ["node", "server/index.js"]
