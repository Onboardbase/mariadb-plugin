#!/bin/bash

set -e

# Define variables
PLUGIN_NAME="obb-key-management-plugin"
PLUGIN_SOURCE_FILE="obb-key-management-plugin.c"
PLUGIN_OUTPUT_FILE="${PLUGIN_NAME}.so"
MARIADB_INCLUDE_PATH="/usr/include/mysql"
MARIADB_LIB_PATH="/usr/lib/mysql"

# Install necessary dependencies
echo "Installing dependencies..."
sudo apt-get update
sudo apt-get install -y libmariadb-dev libcurl4-openssl-dev gcc make

# Compile the plugin
echo "Compiling the MariaDB plugin..."
gcc -fPIC -shared -o $PLUGIN_OUTPUT_FILE $PLUGIN_SOURCE_FILE -I$MARIADB_INCLUDE_PATH -L$MARIADB_LIB_PATH -lmysqlclient -lcurl

# Output result
if [ -f "$PLUGIN_OUTPUT_FILE" ]; then
    echo "Build successful! Plugin created: $PLUGIN_OUTPUT_FILE"
else
    echo "Build failed!"
    exit 1
fi