FROM node:20-alpine
WORKDIR /app
COPY package.json package-lock.json ./
RUN npm ci --omit=dev
COPY index.js ./
RUN addgroup -S mcp && adduser -S mcp -G mcp
USER mcp
EXPOSE 3000
ENV TRANSPORT_MODE=sse
ENV PORT=3000
CMD ["node", "index.js"]
