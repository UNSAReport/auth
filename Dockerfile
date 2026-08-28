# syntax=docker/dockerfile:1
FROM oven/bun:1-alpine AS base
WORKDIR /app

FROM base AS deps
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

FROM base AS build
COPY --from=deps /app/node_modules ./node_modules
COPY package.json bun.lock tsconfig.json drizzle.config.ts ./
COPY src ./src
RUN bun build --target=bun --minify --outdir=./dist ./src/index.ts

FROM base AS production-deps
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production && bun pm cache rm

FROM base AS release
ENV NODE_ENV=production
ENV IDP_PORT=3000
COPY --from=production-deps /app/node_modules ./node_modules
COPY --from=build /app/dist ./dist
COPY package.json ./
COPY src/db/migrations ./src/db/migrations
COPY drizzle.config.ts ./
RUN chown -R bun:bun /app
USER bun

HEALTHCHECK --interval=30s --timeout=3s --start-period=15s --retries=3 \
  CMD bun -e "fetch('http://127.0.0.1:'+(process.env.IDP_PORT||3000)+'/').then(r=>{if(!r.ok)process.exit(1)}).catch(()=>process.exit(1))"
CMD ["bun", "./dist/index.js"]
