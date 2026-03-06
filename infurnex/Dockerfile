FROM python:3.11-slim

# Prevent python from writing pyc files
ENV PYTHONDONTWRITEBYTECODE 1
# Ensure python output is sent straight to terminal
ENV PYTHONUNBUFFERED 1

# Set working directory
WORKDIR /app

# Install dependencies
COPY requirements.txt /app/
RUN pip install --no-cache-dir -r requirements.txt

# Copy everything
COPY . /app/

# Set the default command to run the tool (if executed container-first)
CMD ["python", "run_challenge.py"]
