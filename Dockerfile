FROM golang:1.23-alpine AS build
WORKDIR /src
COPY go.mod go.sum *.go ./
RUN go mod tidy && CGO_ENABLED=0 go build -ldflags="-s -w" -o /sidecar .

FROM gcr.io/distroless/static
COPY --from=build /sidecar /sidecar
EXPOSE 8080
ENTRYPOINT ["/sidecar"]