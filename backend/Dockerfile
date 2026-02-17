FROM python:3.12-slim

# Install system dependencies (libpcap for packet processing tools like cicflowmeter)
RUN apt-get update && apt-get install -y libpcap-dev gcc && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Upgrade pip
RUN pip install --upgrade pip

# Copy only requirements first to leverage Docker cache
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the entire project
COPY . .

# Expose the API port
EXPOSE 8000

# Command to run the backend (from the root 'nal' directory context)
CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]
