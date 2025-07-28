# Use a small base image that includes a shell and package manager
FROM python:3.9-alpine

# Install curl and jq for the entrypoint script
RUN apk --no-cache add curl jq

# Install Python and pip for the goth binary dependencies
RUN pip install requests

# Copy the entrypoint script from its location in the project.
COPY ./entrypoint.sh /entrypoint.sh

# Copy the setup.py file to the container
COPY ./setup.py /setup.py

# Copy the users.txt file to the container
COPY ./users.txt /users.txt

# Make the entrypoint script executable
RUN chmod +x /entrypoint.sh

# Set the entrypoint to our script
ENTRYPOINT ["/entrypoint.sh"]
