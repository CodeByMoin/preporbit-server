# 1. Use full Debian image
FROM debian:bullseye

# 2. Set up Node manually
RUN apt-get update && apt-get install -y curl gnupg && \
  curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
  apt-get install -y nodejs

# 2. Install texlive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      texlive-latex-base \
      texlive-latex-recommended \
      texlive-latex-extra \
      texlive-fonts-recommended \
      texlive-fonts-extra \
      texlive-xetex \
      ghostscript \
      poppler-utils \
      make \
      nodejs \
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
