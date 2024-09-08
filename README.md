Build Process
You will need to compile both the service logic (obb_key_service.c) and the plugin (mariadb_plugin.c). To do this, you can follow these steps:

### 1. Create a Static Library for the Service Logic
First, compile the service logic into a static library that you can link against:

```bash
gcc -c obb_key_service.c -o obb_key_service.o -lcurl
ar rcs libobb_key_service.a obb_key_service.o
```
This creates a static library libobb_key_service.a that contains the service logic.

### 2. Compile the MariaDB Plugin
Now, compile the MariaDB plugin and link it against the libobb_key_service.a static library:

```bash
gcc -o mariadb_plugin.so mariadb_plugin.c -L. -lobb_key_service -lcurl -fPIC -shared
```

-L. tells the compiler to look for libraries in the current directory.
-lobb_key_service links the libobb_key_service.a library.
-lcurl links the libcurl library.
-fPIC -shared creates a shared object (.so file), which is required for MariaDB plugins.

### Step 3: Run the Plugin in MariaDB
Once the plugin is built, you can install it in MariaDB using the following SQL command:

```sql

INSTALL PLUGIN store_key_plugin SONAME 'mariadb_plugin.so';
```
### Step 4: Test the Plugin
You can configure the URL, API key, and requested key in your my.cnf file or directly in MariaDB using:

```sql
SET GLOBAL store_url = 'https://public.onboardbase.com/api/v1/store/get';
SET GLOBAL store_api_key = 'your_api_key';
```

MariaDB will now use your plugin to fetch the key for encryption. You can also debug the output by checking the logs where printf outputs are written.

### Step 5: Automate with a Bash Script
To automate the build process for GitHub Actions, create a build.sh script:

```bash
#!/bin/bash
set -e

# Compile service logic
gcc -c obb_key_service.c -o obb_key_service.o -lcurl
ar rcs libobb_key_service.a obb_key_service.o

# Compile MariaDB plugin
gcc -o mariadb_plugin.so mariadb_plugin.c -L. -lobb_key_service -lcurl -fPIC -shared

echo "Build complete. Plugin created: mariadb_plugin.so"
```
Add this build.sh script to your GitHub Actions workflow for automated building.
