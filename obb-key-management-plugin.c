#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include <mysql/plugin.h>
#include <mysql/plugin_audit.h>

static char store_server_url[1024] = "https://public.onboardbase.com/api/v1/store/get";

static char secret_key[256];

static char api_key[256] = "";


size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total_size = size * nmemb;
    if (total_size < sizeof(secret_key) - 1) {
        strncpy(secret_key, (char *)ptr, total_size);
        secret_key[total_size] = '\0';
    }
    return total_size;
}

int fetch_secret_key() {
    CURL *curl;
    CURLcode res;

    struct curl_slist *headers = NULL;
    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        curl_easy_setopt(curl, CURLOPT_URL, store_server_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        if (strlen(api_key) > 0) {
            char header[512];
            snprintf(header, sizeof(header), "API_KEY: %s", api_key);
            headers = curl_slist_append(headers, header);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }

        res = curl_easy_perform(curl);

        if (res != CURLE_OK) {
            fprintf(stderr, "CURL error: %s\n", curl_easy_strerror(res));
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return 1;
        }

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return 0;
}

static int kv_key_plugin_init(void *p) {
    if (fetch_secret_key() != 0) {
        fprintf(stderr, "Failed to fetch the secret key from the Onboardbase Store server.\n");
        return 1;
    }
    printf("Secret key fetched successfully: %s\n", secret_key);
    return 0;
}

static int kv_key_plugin_deinit(void *p) {

    return 0;
}


static MYSQL_SYSVAR_STR(
    store_url,               // Variable name in MariaDB
    store_server_url,        // The C variable it maps to
    PLUGIN_VAR_RQCMDARG,  // Read-only variable, can be set at startup
    "URL of the Store server for fetching encryption key",
    NULL,  // Validation function (if needed)
    NULL,  // Update function (if needed)
    "https://public.onboardbase.com/api/v1/store/get"  // Default value
);

static MYSQL_SYSVAR_STR(
    store_api_key,           // Variable name in MariaDB
    api_key,              // The C variable it maps to
    PLUGIN_VAR_RQCMDARG,  // Read-only variable, can be set at startup
    "API key for the Store server",
    NULL,  // Validation function (if needed)
    NULL,  // Update function (if needed)
    ""     // Default value
);

// Define the system variable list
static struct st_mysql_sys_var *kv_key_plugin_system_variables[] = {
    MYSQL_SYSVAR(store_url),
    MYSQL_SYSVAR(store_api_key),
    NULL
};

// Plugin type declaration
mysql_declare_plugin(store_key_plugin)
{
    MYSQL_STORAGE_ENGINE_PLUGIN,
    &store_key_plugin_info,
    "OBB-KEY-MANAGEMENT",
    "Onboardbase",
    "Fetches secret key from Store server for encryption",
    PLUGIN_LICENSE_GPL,
    kv_key_plugin_init,     // Plugin init function
    kv_key_plugin_deinit,   // Plugin deinit function
    0x0001,                 // Version
    NULL,                   // status variables
    kv_key_plugin_system_variables,  // system variables
    NULL,                   // reserved
    0                       // flags
}
mysql_declare_plugin_end;