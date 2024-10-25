# Use a lightweight Debian-based image
FROM debian:bullseye-slim

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    python3 \
    python3-pip \
    libusb-1.0-0-dev \
    git \
    build-essential \
    usbmuxd \
    libplist-utils \
    libusbmuxd-tools \
    ideviceinstaller \
    libimobiledevice-utils \
    ssh

# Set working directory
WORKDIR /app

# Copy project files
COPY . /app

# Install Python dependencies
RUN pip3 install --no-cache-dir --upgrade pip && \
    pip3 install --no-cache-dir -r requirements.txt

# Expose Streamlit default port
EXPOSE 8501

# Start the Streamlit app
CMD ["streamlit", "run", "main.py"]
