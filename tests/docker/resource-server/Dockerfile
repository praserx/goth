# Use the official Nginx image from Docker Hub
FROM nginx:alpine

# Remove the default Nginx welcome page
RUN rm -rf /usr/share/nginx/html/*

# Copy the sample HTML content to the Nginx web root directory
COPY html/ /usr/share/nginx/html/

# Expose port 80 to allow traffic to Nginx
EXPOSE 80

# The default command for the nginx container is to start the server.
# CMD ["nginx", "-g", "daemon off;"]
