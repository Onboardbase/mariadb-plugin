# Use Ubuntu as the base image
FROM ubuntu:20.04

# Set non-interactive environment for package installation
ENV DEBIAN_FRONTEND=noninteractive

# Update package repository and install dependencies
RUN apt-get update && apt-get install -y \
    build-essential \
    libmysqlclient-dev \
    libcurl4-openssl-dev \
    gcc \
    cmake \
    wget \
    curl \
    git \
    mariadb-server \
    mariadb-plugin-mroonga

# Create a working directory
WORKDIR /usr/src/app

# Copy the source code into the container
COPY . /usr/src/app

# Compile the plugin
RUN gcc -I/usr/include/mysql \
        -L/usr/lib/x86_64-linux-gnu \
        -o mariadb_plugin.so mariadb_plugin.c obb_key_service.c \
        -lmysqlclient -lcurl -fPIC -shared

# Run MariaDB in the foreground to test the plugin
CMD ["mysqld"]
