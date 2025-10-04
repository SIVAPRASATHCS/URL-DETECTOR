# Manual Docker Commands for Deployment

# 1. Install Docker Desktop for Windows
# Download from: https://www.docker.com/products/docker-desktop/

# 2. Build the image
docker build -t phishing-detector .

# 3. Run the container
docker run -d -p 8000:8000 --name phishing-api phishing-detector

# 4. Check status
docker ps

# 5. View logs
docker logs phishing-api

# 6. Stop container
docker stop phishing-api

# 7. Remove container
docker rm phishing-api