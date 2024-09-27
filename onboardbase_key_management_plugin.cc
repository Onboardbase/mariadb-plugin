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
#include <stack>

#define PLUGIN_ERROR_HEADER "onboardbase: "
#define MAX_RESPONSE_SIZE 131072
#define MAX_URL_SIZE 32768

typedef struct KEY_INFO
{
  unsigned int key_id;
  unsigned int key_version;
  clock_t timestamp;
  unsigned int length;
  unsigned char data [MY_AES_MAX_KEY_LENGTH];
  KEY_INFO() : key_id(0), key_version(0), timestamp(0), length(0) {};
  KEY_INFO(unsigned int key_id_,
           unsigned int key_version_,
           clock_t timestamp_,
           unsigned int length_) :
    key_id(key_id_), key_version(key_version_),
    timestamp(timestamp_), length(length_) {};
} KEY_INFO;

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
    OBData()
     :slist(NULL),
     vault_url_data(NULL),
     vault_url_len(0),
     local_token(NULL),
     token_header(NULL),
     curl_inited(false)
   {}
    unsigned int get_key_from_vault(unsigned int version, unsigned int key_id, unsigned char *dstbuf, unsigned int *buflen);
    unsigned int get_latest_version();
    int init();
    void deinit()
    {
    if (slist)
    {
      curl_slist_free_all(slist);
      slist = NULL;
    }
    if (curl_inited)
    {
      curl_global_cleanup();
      curl_inited = false;
    }
    vault_url_len = 0;
    if (vault_url_data)
    {
      free(vault_url_data);
      vault_url_data = NULL;
    }
    if (token_header)
    {
      free(token_header);
      token_header = NULL;
    }
    if (local_token)
    {
      free(local_token);
      local_token = NULL;
    }
  }

private:
    int curl_run(const char *url, std::string *response) const;
    void *alloc (size_t nbytes) const
    {
    void *res = (char *) malloc(nbytes);
    if (!res)
    {
      my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                      "Memory allocation error", 0);
    }
    return res;
    }
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


static size_t write_response_memory (void *contents, size_t size, size_t nmemb,
                                     void *userp)
{
  size_t realsize = size * nmemb;
  std::ostringstream *read_data = static_cast<std::ostringstream *>(userp);
  size_t current_length = read_data->tellp();
  if (current_length + realsize > MAX_RESPONSE_SIZE)
    return 0; // response size limit exceeded
  read_data->write(static_cast<char *>(contents), realsize);
  if (!read_data->good())
    return 0;
  return realsize;
}

enum {
   OPERATION_OK,
   OPERATION_TIMEOUT,
   OPERATION_ERROR
};

static CURLcode
  perform_with_retries (CURL *curl, std::ostringstream *read_data_stream)
{
  int retries= max_retries;
  CURLcode curl_res;
  do {
    curl_res= curl_easy_perform(curl);
    if (curl_res != CURLE_OPERATION_TIMEDOUT)
    {
      break;
    }
    read_data_stream->clear();
    read_data_stream->str("");
  } while (retries--);
  return curl_res;
}


int OBData::curl_run (const char *url, std::string *response) const
{
  char curl_errbuf[CURL_ERROR_SIZE];
  std::ostringstream read_data_stream;
  long http_code = 0;
  CURLcode curl_res = CURLE_OK;
  CURL *curl = curl_easy_init();
  if (curl == NULL)
  {
    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                    "Cannot initialize curl session",
                    ME_ERROR_LOG_ONLY);
    return OPERATION_ERROR;
  }
  curl_errbuf[0] = '\0';
  if ((curl_res= curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curl_errbuf)) !=
          CURLE_OK ||
      (curl_res= curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                                  write_response_memory)) != CURLE_OK ||
      (curl_res= curl_easy_setopt(curl, CURLOPT_WRITEDATA,
                                  &read_data_stream)) !=
          CURLE_OK ||
      (curl_res= curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist)) !=
          CURLE_OK ||
      (curl_res= curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL)) !=
          CURLE_OK ||
      (curl_res= curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L)) !=
          CURLE_OK ||
      (timeout &&
       ((curl_res= curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, timeout)) !=
            CURLE_OK ||
        (curl_res= curl_easy_setopt(curl, CURLOPT_TIMEOUT, timeout)) !=
            CURLE_OK)) ||
      (curl_res = curl_easy_setopt(curl, CURLOPT_URL, url)) != CURLE_OK ||
      (curl_res = perform_with_retries(curl, &read_data_stream)) != CURLE_OK ||
      (curl_res = curl_easy_getinfo (curl, CURLINFO_RESPONSE_CODE,
                                     &http_code)) != CURLE_OK)
  {
    curl_easy_cleanup(curl);
    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                    "curl returned this error code: %u "
                    "with the following error message: %s", 0, curl_res,
                    curl_errbuf[0] ? curl_errbuf :
                                     curl_easy_strerror(curl_res));
    return OPERATION_ERROR;
  }
  curl_easy_cleanup(curl);
  *response = read_data_stream.str();
  bool is_error = http_code < 200 || http_code >= 300;
  if (is_error)
  {
    const char *res = response->c_str();
    /*
      Error 404 requires special handling - we should ignore this
      error at this level, since this means the missing key (this
      problem is handled at a higher level)
    */
    if (http_code == 404)
    {
      *response = std::string("");
      is_error = false;
    }
    else if (is_error)
    {
      my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                      "Onboardbase server error: %d, response: %s",
                      ME_ERROR_LOG_ONLY | ME_WARNING, http_code, res);
    }
  }
  return is_error ? OPERATION_ERROR : OPERATION_OK;
}


std::string OBData::extract_value(const std::string &json_str, const std::string &key) {
    // Search for the outer key in the JSON string
    std::string search_key = "\"" + key + "\":";
    size_t start = json_str.find(search_key);
    if (start == std::string::npos) return "";  // Key not found

    start += search_key.length();

    // Handle nested object values, e.g., "key": { "inner_key": "value" }
    if (json_str[start] == '{') {
        // Use a stack to match nested brackets and extract the full object value
        std::stack<char> bracket_stack;
        size_t obj_start = start;
        bracket_stack.push('{');
        ++start;

        // Traverse the JSON to find the matching closing bracket
        while (!bracket_stack.empty() && start < json_str.length()) {
            if (json_str[start] == '{') {
                bracket_stack.push('{');
            } else if (json_str[start] == '}') {
                bracket_stack.pop();
            }
            ++start;
        }

        // Return the nested JSON object as a string
        return json_str.substr(obj_start, start - obj_start);
    }
    
    // Otherwise, handle primitive values, e.g., "key": "value" or "key": number
    // Skip any spaces or quotes
    while (json_str[start] == ' ' || json_str[start] == '\"') ++start;

    size_t end = start;

    // Handle string values enclosed in quotes
    if (json_str[start] == '\"') {
        ++start;
        end = json_str.find("\"", start);
        if (end == std::string::npos) return "";  // Unterminated string value
    } else {
        // Handle non-string values (numbers, booleans, etc.)
        while (end < json_str.length() && json_str[end] != ',' && json_str[end] != '}' && json_str[end] != ' ') ++end;
    }

    return json_str.substr(start, end - start);
}

unsigned int OBData::get_latest_version()
{
  std::string url = std::string(vault_url_data);
    std::string response;
    
    if (curl_run(url.c_str(), &response) != OPERATION_OK) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Unable to get key data", 0);
        return ENCRYPTION_KEY_VERSION_INVALID;
    }

    std::string data_value = extract_value(response, "data");
    if (data_value.empty() || data_value == "null") {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Unable to get data object (http response is: %s)", 0, response.c_str());
        return ENCRYPTION_KEY_VERSION_INVALID;
    }

    std::string key_value = extract_value(data_value, "value");
    if (key_value.empty() || key_value == "null") {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Unable to get value string (http response is: %s)", 0, response.c_str());
        return ENCRYPTION_KEY_VERSION_INVALID;
    }

    return 0;
}


unsigned int OBData::get_key_from_vault(unsigned int version, unsigned int key_id, unsigned char *dstbuf, unsigned int *buflen) {

    std::string url = std::string(vault_url_data);
    std::string response;
    
    if (curl_run(url.c_str(), &response) != OPERATION_OK) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Unable to get key data", 0);
        return ENCRYPTION_KEY_VERSION_INVALID;
    }

    std::string data_value = extract_value(response, "data");
    if (data_value.empty() || data_value == "null") {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Unable to get data object (http response is: %s)", 0, response.c_str());
        return ENCRYPTION_KEY_VERSION_INVALID;
    }

    std::string key_value = extract_value(data_value, "value");
    if (key_value.empty() || key_value == "null") {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Unable to get value string (http response is: %s)", 0, response.c_str());
        return ENCRYPTION_KEY_VERSION_INVALID;
    }

    *buflen = key_value.length();
    KEY_INFO info(1, 1, clock(), *buflen);
    memcpy(info.data, dstbuf, *buflen);
    return 0;
}


static unsigned int get_key_from_vault(unsigned int version, unsigned int key_id, unsigned char *dstbuf, unsigned int *buflen) {
    return data.get_key_from_vault(version, key_id, dstbuf, buflen);
}

unsigned int get_latest_version(unsigned int key_id)
{
    return data.get_latest_version();
}

struct st_mariadb_encryption onboardbase_key_management_plugin = {
    MariaDB_ENCRYPTION_INTERFACE_VERSION,
    get_latest_version,
    get_key_from_vault,
    0, 0, 0, 0, 0
};

int OBData::init() {

    const char *x_vault_token = "store_key:";
    size_t token_len = strlen(token);

    if (token_len == 0) {
        char *token_env = getenv("VAULT_TOKEN");
        if (token_env) {
            token_len = strlen(token_env);
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

    // Allocate and construct token header
    size_t buf_len = strlen(x_vault_token) + token_len + 1;
    token_header = (char *)alloc(buf_len);
    if (!token_header) return 1;
    snprintf(token_header, buf_len, "%s%s", x_vault_token, token);

    // Allocate vault_url_data
    vault_url_len = strlen(vault_url);
    vault_url_data = (char *)alloc(vault_url_len + 1);
    if (!vault_url_data) return 1;
    snprintf(vault_url_data, vault_url_len + 1, "%s", vault_url);

    if (curl_global_init(CURL_GLOBAL_ALL) != CURLE_OK) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "Unable to initialize curl library", 0);
        return 1;
    }
    curl_inited = true;

    // Construct slist with token_header
    slist = curl_slist_append(NULL, token_header);
    if (!slist) {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER "curl: unable to construct slist", 0);
        return 1;
    }

    return 0;
}

static int onboardbase_key_management_plugin_init(void *p) {
  int rc = data.init();
  if (rc)
  {
    data.deinit();
  }
  return rc;
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