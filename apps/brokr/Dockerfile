# Build the service from TypeScript sources
FROM node:24.21.0-bookworm-slim AS build

WORKDIR /app

RUN corepack enable pnpm && corepack prepare pnpm@10.20.0 --activate

# Copy workspace manifests to resolve package dependencies
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml tsconfig.base.json ./
COPY apps/brokr/package.json apps/brokr/
COPY apps/tradr/package.json apps/tradr/
COPY packages/protocol/package.json packages/protocol/
COPY packages/brokr-client/package.json packages/brokr-client/
COPY packages/ui/package.json packages/ui/
COPY packages/client-state/package.json packages/client-state/

RUN pnpm install --filter @tradr/brokr... --frozen-lockfile

# Compile TypeScript source files to JavaScript
COPY apps/brokr/tsconfig.json apps/brokr/
COPY apps/brokr/src apps/brokr/src

RUN pnpm --filter @tradr/brokr build

# Isolate production dependencies to keep the runtime footprint small
FROM node:24.21.0-bookworm-slim AS prod-deps

WORKDIR /app

RUN corepack enable pnpm && corepack prepare pnpm@10.20.0 --activate

COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
COPY apps/brokr/package.json apps/brokr/
COPY apps/tradr/package.json apps/tradr/
COPY packages/protocol/package.json packages/protocol/
COPY packages/brokr-client/package.json packages/brokr-client/
COPY packages/ui/package.json packages/ui/
COPY packages/client-state/package.json packages/client-state/

RUN pnpm install --filter @tradr/brokr... --prod --frozen-lockfile

# Runtime stage serving the Brokr as an unprivileged user
FROM node:24.21.0-bookworm-slim AS runtime

WORKDIR /app/apps/brokr

ENV NODE_ENV=production \
    BROKR_DATA_DIR=/data \
    BROKR_HOST=0.0.0.0 \
    BROKR_PORT=8780

RUN mkdir -p /data && chown -R node:node /data

COPY --from=prod-deps --chown=node:node /app/node_modules /app/node_modules
COPY --from=prod-deps --chown=node:node /app/apps/brokr/node_modules /app/apps/brokr/node_modules
COPY --from=build --chown=node:node /app/apps/brokr/package.json /app/apps/brokr/package.json
COPY --from=build --chown=node:node /app/apps/brokr/dist /app/apps/brokr/dist

USER node

EXPOSE 8780

# Persist database state across container recreations
VOLUME /data

# Query health check endpoint directly using Node to avoid external dependencies
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD ["node", "-e", "fetch('http://127.0.0.1:8780/v1/health').then(r => { if (!r.ok) process.exit(1); }).catch(() => process.exit(1))"]

CMD ["node", "dist/index.js"]
