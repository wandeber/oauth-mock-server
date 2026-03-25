FROM node:22-alpine AS build

WORKDIR /app
COPY package*.json ./
RUN npm ci

COPY tsconfig.json ./
COPY src ./src
RUN npm run build

FROM node:22-alpine

WORKDIR /app
ENV NODE_ENV=production
# The runtime image must be self-contained, so it always boots with a repo fixture instead of a local ignored file.
ENV MOCK_OAUTH_CONFIG_FILE=/app/test-fixtures/docker-config.json

COPY --from=build /app/dist ./dist
COPY test/fixtures ./test-fixtures

EXPOSE 8787
CMD ["node", "dist/server.js"]
