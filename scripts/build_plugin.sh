#!/bin/bash

set -e

# Define variables
PLUGIN_NAME="obb-key-plugin"
PLUGIN_SOURCE_FILE="mariadb_plugin.c"
PLUGIN_OUTPUT_FILE="${PLUGIN_NAME}.so"
MARIADB_INCLUDE_PATH="/usr/mysql/include"
MARIADB_LIB_PATH="/usr/mysql/lib"

# Install necessary dependencies
echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y libcurl4-openssl-dev gcc make libmysqlclient-dev

echo "Compiling the Obb Service lib..."
gcc -c obb_key_service.c -o obb_key_service.o -lcurl
ar rcs libobb_key_service.a obb_key_service.o

# Compile the plugin
echo "Compiling the MariaDB plugin..."
gcc -fPIC -shared -o -lobb_key_service $PLUGIN_OUTPUT_FILE $PLUGIN_SOURCE_FILE -I$MARIADB_INCLUDE_PATH -L$MARIADB_LIB_PATH -lmysqlclient -lcurl

# Output result
if [ -f "$PLUGIN_OUTPUT_FILE" ]; then
    echo "Build successful! Plugin created: $PLUGIN_OUTPUT_FILE"
else
    echo "Build failed!"
    exit 1
fi