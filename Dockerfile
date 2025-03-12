# Use an official Node runtime as a parent image
FROM denoland/deno:2.2.3

# Set the working directory in the container
WORKDIR /usr/src/app

# Copy package.json and package-lock.json (or use yarn.lock if using yarn)
COPY package*.json ./

# Install any needed packages
RUN deno install

# Bundle app source inside the Docker image
COPY index.js ./
COPY ./public ./public
COPY config.json ./config.json

# Change ownership of the working directory to the 'node' user
RUN chown -R deno:deno /usr/src/app

# Switch to 'node' user
USER deno

# Define environment variable
ENV PORT=8000
ENV ENV=production

EXPOSE 8000
# Run the app when the container launches
CMD ["deno", "run","--allow-net", "--allow-write", "--allow-env", "--allow-read", "--allow-sys", "--unstable-cron", "index.js"] 
