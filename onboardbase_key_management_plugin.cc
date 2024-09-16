#include <mysql/plugin_encryption.h>
#include <mysqld_error.h>
#include <my_alloca.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <time.h>
#include <errno.h>
#include <string>
#include <sstream>
#include <curl/curl.h>
#include <algorithm>
#include <unordered_map>
#include <mutex>

#define PLUGIN_ERROR_HEADER "onboardbase: "
#define MAX_RESPONSE_SIZE 131072
#define MAX_URL_SIZE 32768

class OBData
{
private:
    struct curl_slist *slist;
    char *vault_url_data;
    size_t vault_url_len;
    char *local_token;
    char *token_header;
    bool curl_inited;

public:
    OBData();
    ~OBData();
    unsigned int get_key_from_vault(unsigned int version, unsigned int key_id, unsigned char *dstbuf, unsigned int *buflen);
    int init();
    void deinit();

private:
    int curl_run(const char *url, std::string *response) const;
    void *alloc(size_t nbytes) const;
    static size_t write_response_memory(void *contents, size_t size, size_t nmemb, void *userp);
    static std::string extract_value(const std::string &json_str, const std::string &key);
};

static OBData data;

static char* vault_url;
static char* token;
static int timeout;
static int max_retries;

// System variables definitions
static MYSQL_SYSVAR_STR(vault_url, vault_url,
    PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
    "HTTP[s] URL that is used to connect to the Onboardbase Store server",
    NULL, NULL, "");

static MYSQL_SYSVAR_STR(token, token,
    PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY | PLUGIN_VAR_NOSYSVAR,
    "Authentication token that passed to the Onboardbase Store in the request header",
    NULL, NULL, "");

static MYSQL_SYSVAR_INT(timeout, timeout,
    PLUGIN_VAR_RQCMDARG,
    "Duration (in seconds) for the Onboardbase Store server connection timeout",
    NULL, NULL, 15, 0, 86400, 1);

static MYSQL_SYSVAR_INT(max_retries, max_retries,
    PLUGIN_VAR_RQCMDARG,
    "Number of server request retries in case of timeout",
    NULL, NULL, 3, 0, INT_MAX, 1);

static struct st_mysql_sys_var *settings[] = {
    MYSQL_SYSVAR(vault_url),
    MYSQL_SYSVAR(token),
    MYSQL_SYSVAR(timeout),
    MYSQL_SYSVAR(max_retries),
    NULL
};

OBData::OBData()
    : slist(NULL), vault_url_data(NULL), vault_url_len(0),
      local_token(NULL), token_header(NULL), curl_inited(false) {}

OBData::~OBData() {
    deinit();
}

void OBData::deinit() {
    if (slist) {
        curl_slist_free_all(slist);
        slist = NULL;
    }
    if (curl_inited) {
        curl_global_cleanup();
        curl_inited = false;
    }
    free(vault_url_data);
    free(token_header);
    free(local_token);
    vault_url_data = NULL;
    token_header = NULL;
    local_token = NULL;
    vault_url_len = 0;
}

void *OBData::alloc(size_t nbytes) const {
    void *res = malloc(nbytes);
    if (!res) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Memory allocation error", 0);
    }
    return res;
}

size_t OBData::write_response_memory(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t realsize = size * nmemb;
    std::ostringstream *read_data = static_cast<std::ostringstream *>(userp);
    size_t current_length = read_data->tellp();
    if (current_length + realsize > MAX_RESPONSE_SIZE)
        return 0; // response size limit exceeded
    read_data->write(static_cast<char *>(contents), realsize);
    return read_data->good() ? realsize : 0;
}

int OBData::curl_run(const char *url, std::string *response) const {
    CURL *curl = curl_easy_init();
    if (!curl) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Cannot initialize curl session", ME_ERROR_LOG_ONLY);
        return 1;
    }

    std::ostringstream read_data_stream;
    char curl_errbuf[CURL_ERROR_SIZE] = {0};

    curl_easy_setopt(curl, CURLOPT_URL, url);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_memory);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_data_stream);
    curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
    curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

    CURLcode res;
    int retries = max_retries;
    do {
        res = curl_easy_perform(curl);
        if (res != CURLE_OPERATION_TIMEDOUT) break;
        read_data_stream.str("");
        read_data_stream.clear();
    } while (--retries >= 0);

    long http_code = 0;
    curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "curl error: %s", ME_ERROR_LOG_ONLY, curl_errbuf[0] ? curl_errbuf : curl_easy_strerror(res));
        return 1;
    }

    if (http_code < 200 || http_code >= 300) {
        if (http_code != 404) {
            my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                            "HTTP error: %ld, response: %s", ME_ERROR_LOG_ONLY | ME_WARNING,
                            http_code, read_data_stream.str().c_str());
            return 1;
        }
        read_data_stream.str("");
    }

    *response = read_data_stream.str();
    return 0;
}

std::string OBData::extract_value(const std::string &json_str, const std::string &key) {
    std::string search_key = "\"" + key + "\":\"";
    size_t start = json_str.find(search_key);
    if (start == std::string::npos) return "";
    start += search_key.length();
    size_t end = json_str.find("\"", start);
    if (end == std::string::npos) return "";
    return json_str.substr(start, end - start);
}

unsigned int OBData::get_key_from_vault(unsigned int version, unsigned int key_id, unsigned char *dstbuf, unsigned int *buflen) {
    // The implementation remains largely the same, but we'll add a version check
    if (version != 1) {
        // Handle unsupported version
        return ENCRYPTION_KEY_VERSION_INVALID;
    }

    std::string url = std::string(vault_url_data) + std::to_string(key_id);
    std::string response;

    if (curl_run(url.c_str(), &response) != 0) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Unable to get key data", 0);
        return ENCRYPTION_KEY_VERSION_INVALID;
    }

    std::string data_value = extract_value(response, "data");
    if (data_value.empty()) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Unable to get data object (http response is: %s)", 0, response.c_str());
        return ENCRYPTION_KEY_VERSION_INVALID;
    }

    std::string key_value = extract_value(data_value, "value");
    if (key_value.empty()) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Unable to get value string (http response is: %s)", 0, response.c_str());
        return ENCRYPTION_KEY_VERSION_INVALID;
    }

    *buflen = key_value.length();
    memcpy(dstbuf, key_value.c_str(), *buflen);
    return 0;
}

int OBData::init() {
    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "Starting init function", ME_ERROR_LOG_ONLY);

    const char *x_vault_token = "store_key:";
    size_t token_len = strlen(token);

    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "Checking token length", ME_ERROR_LOG_ONLY);

    if (token_len == 0) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "Token is empty, checking VAULT_TOKEN environment variable", ME_ERROR_LOG_ONLY);

        char *token_env = getenv("VAULT_TOKEN");
        if (token_env) {
            token_len = strlen(token_env);
            my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "Found VAULT_TOKEN in environment", ME_ERROR_LOG_ONLY);
            
            if (token_len != 0) {
                local_token = strdup(token_env);
                if (!local_token) return 1;
                token = local_token;
            }
        }

        if (token_len == 0) {
            my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "Both token and VAULT_TOKEN environment variable are empty", 0);
            return 1;
        }
    }

    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "Constructing token header", ME_ERROR_LOG_ONLY);

    size_t buf_len = strlen(x_vault_token) + token_len + 1;
    token_header = (char *)alloc(buf_len);
    if (!token_header) return 1;
    snprintf(token_header, buf_len, "%s%s", x_vault_token, token);

    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "Token header constructed successfully", ME_ERROR_LOG_ONLY);

    vault_url_len = strlen(vault_url);
    vault_url_data = (char *)alloc(vault_url_len + 1);
    if (!vault_url_data) return 1;
    snprintf(vault_url_data, vault_url_len + 1, "%s", vault_url);

    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "Vault URL prepared", ME_ERROR_LOG_ONLY);

    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "Unable to initialize curl library", 0);
        return 1;
    }
    curl_inited = true;

    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "cURL library initialized", ME_ERROR_LOG_ONLY);

    slist = curl_slist_append(NULL, token_header);
    if (!slist) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "curl: unable to construct slist", 0);
        return 1;
    }

    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "Header list constructed successfully", ME_ERROR_LOG_ONLY);

    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "Init function completed", ME_ERROR_LOG_ONLY);
    return 0;
}
static unsigned int get_key_from_vault(unsigned int version, unsigned int key_id, unsigned char *dstbuf, unsigned int *buflen) {
    return data.get_key_from_vault(version, key_id, dstbuf, buflen);
}

struct st_mariadb_encryption onboardbase_key_management_plugin = {
    MariaDB_ENCRYPTION_INTERFACE_VERSION,
    NULL, // get_latest_version is not implemented
    get_key_from_vault,
    NULL, NULL, NULL, NULL, NULL
};

static int onboardbase_key_management_plugin_init(void *p) {
    return data.init();
}

static int onboardbase_key_management_plugin_deinit(void *p) {
    data.deinit();
    return 0;
}

maria_declare_plugin(onboardbase_key_management)
{
    MariaDB_ENCRYPTION_PLUGIN,
    &onboardbase_key_management_plugin,
    "onboardbase_key_management",
    "Onboardbase",
    "Onboardbase Store key management plugin",
    PLUGIN_LICENSE_GPL,
    onboardbase_key_management_plugin_init,
    onboardbase_key_management_plugin_deinit,
    0x0100, /* 1.0 */
    NULL,   /* status variables */
    settings,
    "1.0",
    MariaDB_PLUGIN_MATURITY_STABLE
}
maria_declare_plugin_end;