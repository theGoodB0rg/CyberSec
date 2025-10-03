# syntax=docker/dockerfile:1

FROM node:20-bookworm-slim AS client-builder
WORKDIR /app
ENV PUPPETEER_SKIP_CHROMIUM_DOWNLOAD=1

RUN apt-get update && apt-get install -y --no-install-recommends \
      bzip2 \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY package*.json ./
COPY client/package*.json client/
RUN npm install && npm --prefix client install

COPY . .
RUN npm run client:build

FROM node:20-bookworm-slim
WORKDIR /app

RUN apt-get update && apt-get install -y --no-install-recommends \
      python3 python3-pip sqlmap \
      chromium \
      sqlite3 \
      bzip2 \
      ca-certificates \
      libnss3 libatk1.0-0 libx11-xcb1 libxcomposite1 libxcursor1 \
      libxdamage1 libxext6 libxfixes3 libxi6 libxrandr2 libgbm1 \
      libasound2 libpangocairo-1.0-0 libgtk-3-0 libatk-bridge2.0-0 \
      libatspi2.0-0 libxrender1 libpango-1.0-0 libpangoft2-1.0-0 \
      libfontconfig1 libfreetype6 fonts-liberation \
    && rm -rf /var/lib/apt/lists/*

ENV NODE_ENV=production \
    SQLMAP_PATH=/usr/bin/sqlmap \
    PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium \
    PORT=3001

COPY package*.json ./
RUN npm install --omit=dev

COPY --from=client-builder /app/server ./server
COPY --from=client-builder /app/client/dist ./client/dist
COPY --from=client-builder /app/scripts ./scripts
COPY --from=client-builder /app/docs ./docs

EXPOSE 3001
CMD ["node", "server/index.js"]
