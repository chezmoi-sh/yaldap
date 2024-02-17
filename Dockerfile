# ┌───────────────────────────────────────────────────────────────────────────┐
# │ <builder>: build the yaLDAP binary (Go)                                   │
# └───────────────────────────────────────────────────────────────────────────┘
FROM docker.io/library/golang:1.22.0-alpine3.19 as builder

ARG YALDAP_VERSION="latest"

RUN set -eux; \
    apk add --no-cache git;

COPY . /src

WORKDIR /src
RUN set -eux; \
    go build \
        -ldflags " \
            -X github.com/prometheus/common/version.Version=${YALDAP_VERSION} \
            -X github.com/prometheus/common/version.Revision=$(git rev-parse --short HEAD) \
            -X github.com/prometheus/common/version.Branch=$(git rev-parse --abbrev-ref HEAD) \
            -X github.com/prometheus/common/version.BuildUser=$(whoami)@$(hostname) \
            -X github.com/prometheus/common/version.BuildDate=$(date -u +'%Y-%m-%dT%H:%M:%SZ') \
        " \
        -o /src/yaldap ./cmd/yaldap/


# ┌───────────────────────────────────────────────────────────────────────────┐
# │ <runtime>: create the yaLDAP runtime image using all previous stages      │
# └───────────────────────────────────────────────────────────────────────────┘
FROM docker.io/library/alpine:3.19.1

# renovate: datasource=github-tags depName=xunleii/yaldap versioning=semver
ARG YALDAP_VERSION="v0.1.1"

# renovate: datasource=repology depName=alpine_3_19/ca-certificates versioning=loose
ARG CA_CERTIFICATES_VERSION=20230506-r0

RUN set -eux; \
    apk add --no-cache \
        ca-certificates=${CA_CERTIFICATES_VERSION}; \
    \
    addgroup -S -g 64885 yaldap; \
    adduser -S -H -G yaldap -u 64885 yaldap;

COPY --from=builder /src/yaldap /src/LICENSE /opt/yaldap/

ENV PATH=/opt/yaldap:${PATH}

USER yaldap
WORKDIR /opt/yaldap
ENTRYPOINT [ "yaldap" ]

EXPOSE 389
HEALTHCHECK --interval=30s --timeout=30s --start-period=5s --retries=3 \
    CMD nc -z -w 2 localhost 389

# metadata as defined by the Open Container Initiative (OCI) and using the 
# xunleii conventions to keep traceability with the source code.
LABEL \
    org.opencontainers.image.authors="xunleii <xunleii@users.noreply.github.com>" \
    org.opencontainers.image.created="01/01/1970T00:00:00.000" \
    org.opencontainers.image.description="Your identity, your rules." \
    org.opencontainers.image.documentation="https://github.com/xunleii/yaldap" \
    org.opencontainers.image.licenses="AGPL-3.0" \
    org.opencontainers.image.revision="" \
    org.opencontainers.image.source="" \
    org.opencontainers.image.title="yaldap" \
    org.opencontainers.image.url="https://github.com/xunleii/yaldap" \
    org.opencontainers.image.version=${YALDAP_VERSION}
