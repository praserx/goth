# Use a small base image that includes a shell and package manager
FROM python:3.9-alpine

# Install curl and jq for the entrypoint script
RUN apk --no-cache add curl jq

# Install Python and pip for the goth binary dependencies
RUN pip install requests

# Copy the pre-built goth binary from the project root.
# The build context for this Dockerfile is the project root.
COPY ./bin/goth /goth

# Copy the entrypoint script from its location in the project.
COPY ./entrypoint.sh /entrypoint.sh

# Copy the setup.py file to the container
COPY ./setup.py /setup.py

# Copy the users.txt file to the container
COPY ./users.txt /users.txt

# Make the entrypoint script executable
RUN chmod +x /entrypoint.sh

# Expose the default port
EXPOSE 8080

# Set the entrypoint to our script
ENTRYPOINT ["/entrypoint.sh"]

# The default command to run after the entrypoint script finishes.
# This will be executed by the `exec "$@"` line in the entrypoint.
CMD ["/goth"]