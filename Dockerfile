FROM node:18-slim

WORKDIR /app

# 安装基础运行依赖
RUN apt-get update && \
    apt-get install -y --no-install-recommends openssl curl ca-certificates && \
    rm -rf /var/lib/apt/lists/*

COPY package*.json ./
RUN npm install --production

COPY . .
RUN chmod +x index.js

ENV PORT=8080
EXPOSE 8080

CMD ["node", "index.js"]
