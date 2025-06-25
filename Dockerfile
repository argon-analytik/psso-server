FROM golang:1.22 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /usr/local/bin/psso-server ./cmd/local

FROM alpine:3.18
WORKDIR /app
RUN mkdir -p /etc/psso /var/psso
COPY --from=build /usr/local/bin/psso-server /usr/local/bin/psso-server
COPY .env.psso /etc/psso/.env.psso
EXPOSE 9100
ENTRYPOINT ["/usr/local/bin/psso-server"]
