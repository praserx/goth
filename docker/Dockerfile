FROM gcr.io/distroless/static:nonroot

WORKDIR /tmp

COPY bin/goth /goth

EXPOSE 8080

# Healthcheck endpoint is not ready yet, so this is commented out.
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/goth", "--healthcheck"]

USER nonroot

ENTRYPOINT ["/goth"]