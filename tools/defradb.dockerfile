# syntax=docker/dockerfile:1

# An image to run defradb.

# Stage: BUILD
FROM docker.io/golang:1.18 AS BUILD
WORKDIR /repo/
COPY go.mod go.sum Makefile /repo/
RUN make deps:modules
COPY .git/ ./.git/
COPY . .
RUN make build

# Stage: RUN
FROM gcr.io/distroless/base-debian11
WORKDIR /
COPY --from=BUILD /repo/build/defradb /defradb

# Documents which ports are normally used.
# To publish the ports: `docker run -p 9181:9181` ...
EXPOSE 9161
EXPOSE 9171
EXPOSE 9181

# Default command provided for convenience.
# e.g. docker run -p 9181:9181 orpheus.source/defradb  start --url 0.0.0.0:9181
ENTRYPOINT [ "/defradb" ]