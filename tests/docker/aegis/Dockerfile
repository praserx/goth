# Use a small base image that includes a shell and package manager
FROM alpine:latest

# Install curl and jq for the entrypoint script
RUN apk --no-cache add curl jq

# Copy the pre-built aegis binary from the project root.
# The build context for this Dockerfile is the project root.
COPY ./bin/aegis /aegis

# Copy the entrypoint script from its location in the project.
COPY ./entrypoint.sh /entrypoint.sh

# Make the entrypoint script executable
RUN chmod +x /entrypoint.sh

# Expose the default port
EXPOSE 8080

# Set the entrypoint to our script
ENTRYPOINT ["/entrypoint.sh"]

# The default command to run after the entrypoint script finishes.
# This will be executed by the `exec "$@"` line in the entrypoint.
CMD ["/aegis"]