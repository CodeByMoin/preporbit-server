# 1. Base Node image
FROM node:18-slim

# 2. Install texlive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      texlive-latex-base \
      texlive-latex-extra \
      texlive-fonts-recommended \
      texlive-xetex \
      texlive-pictures \
      make \
    && rm -rf /var/lib/apt/lists/*

# 3. Create app dir
WORKDIR /usr/src/app

# 4. Copy deps + install
COPY package*.json ./
RUN npm install --production

# 5. Copy source
COPY . .

# 6. Expose port & start
ENV PORT=3001
EXPOSE 3001
CMD ["node", "server.js"]
