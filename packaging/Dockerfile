# Multi-stage build: Alpine compile, scratch runtime.
# Resulting image is ~900 KB and contains shrike + nothing else.

FROM alpine:3.20 AS build
RUN apk add --no-cache build-base linux-headers
WORKDIR /src
COPY . .
RUN make CC=gcc CFLAGS='-std=c99 -Wall -Wextra -O2 -static -Iinclude -D_GNU_SOURCE'

FROM scratch
COPY --from=build /src/shrike /shrike
ENTRYPOINT ["/shrike"]
