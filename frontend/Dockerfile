FROM node:20-slim

WORKDIR /app

# Copy package files first
COPY package*.json ./

# Install dependencies
RUN npm install

# Copy the rest of the frontend code
COPY . .

# Expose Vite default port
EXPOSE 5173

# Run Vite dev server with --host to expose to network
CMD ["npm", "run", "dev", "--", "--host"]
