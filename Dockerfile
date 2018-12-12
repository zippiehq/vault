FROM node AS builder

WORKDIR /app

COPY *.json /app/
RUN npm install


# Generate third-party licenses file
FROM node AS licenses

WORKDIR /app

COPY --from=builder /app/node_modules /app/node_modules
RUN npm install license-extractor

RUN node_modules/license-extractor/bin/licext --mode output > /app/LICENSE.thirdparties.txt

# Build application
FROM node

WORKDIR /app

COPY --from=builder /app/node_modules /app/node_modules

COPY *.json /app/
COPY webpack.prod.config.js /app/webpack.prod.config.js
COPY zippie.config.js /app/zippie.config.js
COPY version.js /app/version.js
COPY src /app/src
COPY worker /app/worker

# Build
RUN npm run build

# Extract licenses
COPY LICENSE /app/dist/LICENSE.txt
COPY LICENSE.artwork /app/dist/LICENSE.artwork.txt
COPY --from=licenses /app/LICENSE.thirdparties.txt /app/dist/LICENSE.thirdparties.txt

RUN ls -l /app/dist/
