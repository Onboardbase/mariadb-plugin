#include <mariadb/mysql/plugin.h>
#include <mariadb/mysql/plugin_audit.h>
#include "obb_key_service.h"

static char store_server_url[1024] = "https://public.onboardbase.com/api/v1/store/get";
static char api_key[256] = "";
static char secret_key[256] = "";
static char requested_key[256] = "data";

// Initialize the plugin
static int kv_key_plugin_init(void *p) {
    if (fetch_secret_key(store_server_url, api_key, requested_key, secret_key, sizeof(secret_key)) != 0) {
        fprintf(stderr, "Failed to fetch the secret key.\n");
        return 1;
    }
    printf("Secret key fetched successfully: %s\n", secret_key);
    return 0;
}

// Deinitialize function for the plugin
static int kv_key_plugin_deinit(void *p) {
    return 0;
}

// System variables
static MYSQL_SYSVAR_STR(store_url, store_server_url, PLUGIN_VAR_RQCMDARG, "URL of the Store server", NULL, NULL, "https://public.onboardbase.com/api/v1/store/get");
static MYSQL_SYSVAR_STR(store_api_key, api_key, PLUGIN_VAR_RQCMDARG, "API key for the Store server", NULL, NULL, "");

// Plugin type declaration
mysql_declare_plugin(store_key_plugin) {
    MYSQL_STORAGE_ENGINE_PLUGIN,
    &store_key_plugin_info,
    "OBB-KEY-MANAGEMENT",
    "Onboardbase",
    "Fetches secret key from Store server for encryption",
    PLUGIN_LICENSE_GPL,
    kv_key_plugin_init,
    kv_key_plugin_deinit,
    0x0001,
    NULL,
    kv_key_plugin_system_variables,
    NULL,
    0
} mysql_declare_plugin_end;
