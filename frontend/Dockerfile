# Multi-stage build for React frontend
FROM node:20-alpine

WORKDIR /app/frontend

# Copy package files
COPY frontend/package*.json ./

# Install dependencies
RUN npm install

# Copy application code
COPY frontend/ ./

# Expose port
EXPOSE 3000

# Start dev server
CMD ["npm", "run", "dev", "--", "--host"]
