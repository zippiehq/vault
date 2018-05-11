FROM node

WORKDIR /app

# Add sources
ADD dist /app/dist
ADD package.json /app/package.json
ADD webpack.config.js /app/webpack.config.js
ADD src /app/src


# Install dependencies
RUN npm install

# Build
RUN npm run build

RUN ls -l "/app/"

