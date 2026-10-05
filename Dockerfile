# syntax=docker/dockerfile:1

########## build: toolchain + source, compiles the gateway ##########
FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY . .
RUN go vet ./... \
    && go build ./... \
    && go build -trimpath -o /out/gateway ./cmd/gateway

########## app: minimal runtime image ##########
FROM alpine:3.20 AS app
RUN adduser -D -u 10001 gateway
COPY --from=build /out/gateway /usr/local/bin/gateway
USER gateway
EXPOSE 8080 9000
ENTRYPOINT ["gateway"]

########## verify: one-shot tests + in-image build + live smoke ##########
FROM build AS verify
COPY scripts/verify.sh /usr/local/bin/verify.sh
RUN chmod +x /usr/local/bin/verify.sh
ENTRYPOINT ["/usr/local/bin/verify.sh"]
