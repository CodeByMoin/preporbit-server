# 1. Base Node image
FROM node:18-slim

# 2. Install texlive
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      texlive-latex-base \
      texlive-latex-recommended \
      texlive-latex-extra \
      texlive-fonts-recommended \
      texlive-fonts-extra \
      texlive-xetex \
      texlive-pictures \
      texlive-science \
      texlive-pstricks \
      texlive-publishers \
      texlive-humanities \
      texlive-lang-all \
      texlive-bibtex-extra \
      texlive-binaries \
      texlive-formats-extra \
      texlive-font-utils \
      texlive-math-extra \
      texlive-plain-generic \
      texlive-extra-utils \
      make \
      ghostscript \
      poppler-utils \
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
