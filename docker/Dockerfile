
# Hardened minimal Dockerfile for goth
FROM gcr.io/distroless/static:nonroot

# Set working directory for clarity
WORKDIR /tmp

# Copy the pre-built binary from the build context into the image
COPY bin/goth /goth

# Expose the port the application will run on (default: 8080)
EXPOSE 8080

# Healthcheck for container health
# Healthcheck endpoint is not ready yet, so this is commented out.
# HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 CMD ["/goth", "--healthcheck"]

# Set entrypoint for the container
ENTRYPOINT ["/goth"]