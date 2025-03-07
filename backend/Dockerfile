# Use official Node.js image with Debian-based dependencies
FROM node:18-bullseye

# Set working directory inside the container
WORKDIR /app

# Copy package.json and package-lock.json first to leverage Docker caching
COPY package*.json ./

# Install dependencies (including argon2 if listed in package.json)
RUN npm install

# Copy the rest of the application files
COPY . .

# Expose the port Express runs on
EXPOSE 5000

# Start the application
CMD ["npm", "start"]
