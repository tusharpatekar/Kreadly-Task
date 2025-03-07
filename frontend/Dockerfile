# Use official Node.js image
FROM node:18-alpine

# Set working directory inside container
WORKDIR /app

# Copy package.json and package-lock.json
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the entire project
COPY . .

# Build the React project
RUN npm run build

# Serve the build using a lightweight server
RUN npm install -g serve

# Expose the port React runs on
EXPOSE 3000

# Start the React app
CMD ["serve", "-s", "build", "-l", "3000"]
