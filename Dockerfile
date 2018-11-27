FROM node

WORKDIR /app

# Add sources
ADD package.json /app/package.json
ADD webpack.prod.config.js /app/webpack.prod.config.js
ADD zippie.config.js /app/zippie.config.js
ADD version.js /app/version.js
ADD src /app/src
ADD worker /app/worker


# Install dependencies
RUN npm install

# Build
RUN npm run build

RUN ls -l "/app/"

