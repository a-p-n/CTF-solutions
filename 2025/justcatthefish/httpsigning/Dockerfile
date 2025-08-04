FROM node:18-alpine

WORKDIR /app

# Install git, socat and other necessary tools
RUN apk add --no-cache git socat

# Copy package files
COPY package*.json ./
COPY tsconfig.json ./
COPY generate-key.js ./

# Install dependencies
RUN npm install

# Copy source code
COPY src/ ./src/

# We have to do a small mod for web-bot-auth
RUN git clone https://github.com/cloudflare/web-bot-auth.git
RUN cd web-bot-auth && git checkout b03be01
COPY 0001-expose-components.patch ./web-bot-auth/0001-expose-components.patch
RUN cd web-bot-auth && git apply ./0001-expose-components.patch

# Build TypeScript
RUN npm run build

# Create directories for keys
RUN mkdir -p /app/keys

# Default command (will be overridden in docker-compose)
CMD ["node", "--version"]