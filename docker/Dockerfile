# Start from a minimal base image
FROM scratch

# Copy the pre-built binary from the build context into the image.
# The binary is expected to be located at bin/goth in the build context.
COPY bin/goth /goth

# Expose the port the application will run on (defaulting to 8080)
# You may need to adjust this depending on your application's configuration.
EXPOSE 8080

# Set the entrypoint for the container to run the application.
ENTRYPOINT ["/goth"]