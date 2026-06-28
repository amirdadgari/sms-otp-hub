FROM node:24-alpine

WORKDIR /app
COPY package*.json ./
RUN npm ci --omit=dev

COPY src ./src
COPY public ./public

ENV PORT=8080
EXPOSE 8080

CMD ["node", "--experimental-sqlite", "src/server.js"]
