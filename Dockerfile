FROM oven/bun:1-alpine
RUN apk add --no-cache age
WORKDIR /app
COPY package.json bun.lock ./
RUN bun install --frozen-lockfile --production
COPY src/ ./src/
COPY cli/ ./cli/
EXPOSE 3000
CMD ["bun", "run", "src/index.ts"]
