# Knox Security Auditor - Streamlit UI
FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Expose port
EXPOSE 8080

# Run Streamlit (PORT expansion handled by Railway's startCommand)
CMD streamlit run streamlit_app.py --server.address=0.0.0.0 --server.headless=true
