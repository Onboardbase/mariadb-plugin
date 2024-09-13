/* Copyright (C) 2019-2022 MariaDB Corporation

 This program is free software; you can redistribute it and/or modify
 it under the terms of the GNU General Public License as published by
 the Free Software Foundation; version 2 of the License.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU General Public License for more details.

 You should have received a copy of the GNU General Public License
 along with this program; if not, write to the Free Software
 Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1335  USA */

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

#define ONBOARDBASE_DEBUG_LOGGING 0

#define PLUGIN_ERROR_HEADER "onboardbase: "

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
  unsigned int get_key_from_vault (unsigned int key_id,
                                   unsigned char *dstbuf,
                                   unsigned int *buflen);
  int init ();
  void deinit ()
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
  int curl_run (const char *url, std::string *response) const;
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
};

static OBData data;


static char* vault_url;
static char* token;
static int timeout;
static int max_retries;


static MYSQL_SYSVAR_STR(vault_url, vault_url,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY,
  "HTTP[s] URL that is used to connect to the Onboardbase Store server",
  NULL, NULL, "");

static MYSQL_SYSVAR_STR(token, token,
  PLUGIN_VAR_RQCMDARG | PLUGIN_VAR_READONLY | PLUGIN_VAR_NOSYSVAR,
  "Authentication token that passed to the Onboardbase Store "
  "in the request header",
  NULL, NULL, "");

static MYSQL_SYSVAR_INT(timeout, timeout,
  PLUGIN_VAR_RQCMDARG,
  "Duration (in seconds) for the Onboardbase Store server "
  "connection timeout",
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

/*
  Reasonable length limit to protect against accidentally reading
  the wrong key or from trying to overload the server with unnecessary
  work to receive too long responses to requests:
*/
#define MAX_RESPONSE_SIZE 131072

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

int OBData::curl_run (const char *url, std::string *response,
                      bool soft_timeout) const
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
      /*
        The options CURLOPT_SSL_VERIFYPEER and CURLOPT_SSL_VERIFYHOST are
        set explicitly to withstand possible future changes in curl defaults:
      */
      (curl_res= curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1)) !=
          CURLE_OK ||
      (curl_res= curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L)) !=
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
    if (soft_timeout && curl_res == CURLE_OPERATION_TIMEDOUT)
    {
      return OPERATION_TIMEOUT;
    }
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

static int get_data(const std::string &response_str,
                     const char **js, int *js_len,
                     unsigned int key_id)
{
    // Extract the "data" object from the response
    std::string data_value = extract_value(response_str, "data");
    if (data_value.empty())
    {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Unable to get data object (http response is: %s)",
                        0, response_str.c_str());
        return 2;
    }

    *js = data_value.c_str();
    *js_len = data_value.length();
    return 0;
}

static int get_key_data(const char *js, int js_len,
                         const char **key, int *key_len,
                         const std::string &response_str)
{
    // Extract the "value" field from the "data" object
    std::string value = extract_value(std::string(js, js_len), "value");
    if (value.empty())
    {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "Unable to get value string (http response is: %s)",
                        0, response_str.c_str());
        return 1;
    }

    *key = value.c_str();
    *key_len = value.length();
    return 0;
}

// Function to extract value from JSON-like string
std::string extract_value(const std::string &json_str, const std::string &key)
{
    std::string search_key = "\"" + key + "\":\"";
    size_t start = json_str.find(search_key);
    if (start == std::string::npos)
    {
        return ""; // Key not found
    }
    start += search_key.length();
    size_t end = json_str.find("\"", start);
    if (end == std::string::npos)
    {
        return ""; // Malformed JSON
    }
    return json_str.substr(start, end - start);
}

unsigned int OBData::get_key_from_vault (unsigned int key_id,
                                         unsigned char *dstbuf,
                                         unsigned int *buflen)
{
  std::string response_str;

  // Construct the Onboardbase URL directly
  size_t buf_len = vault_url_len + 20 + 1; // URL + key_id + null terminator
  char *url = (char *) alloca(buf_len);
  snprintf(url, buf_len, "%s%u", vault_url_data, key_id); 

  int rc;
  if ((rc = curl_run(url, &response_str)) != OPERATION_OK)
  {
    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                    "Unable to get key data", 0);
    return ENCRYPTION_KEY_VERSION_INVALID;
  }

  const char *js;
  int js_len;
  if (get_data(response_str, &js, &js_len, key_id)) 
  {
    return ENCRYPTION_KEY_VERSION_INVALID;
  }

  const char *key;
  int key_len;
  if (get_key_data(js, js_len, &key, &key_len, response_str))
  {
    return ENCRYPTION_KEY_VERSION_INVALID;
  }

  memcpy(dstbuf, key, key_len);
  *buflen = key_len;
  return 0;
}


static unsigned int get_key_from_vault(unsigned int key_id,
                                        unsigned char *dstbuf,
                                        unsigned int *buflen)
{
  return data.get_key_from_vault(key_id, dstbuf, buflen);
}

struct st_mariadb_encryption onboardbase_key_management_plugin= {
  MariaDB_ENCRYPTION_INTERFACE_VERSION,
  get_latest_version,
  get_key_from_vault,
  0, 0, 0, 0, 0
};

#define MAX_URL_SIZE 32768

int OBData::init ()
{
  const static char *x_vault_token = "store_key:";
  const static size_t x_vault_token_len = strlen(x_vault_token);
  char *token_env= getenv("VAULT_TOKEN");
  size_t token_len = strlen(token);
  if (token_len == 0)
  {
    if (token_env)
    {
      token_len = strlen(token_env);
      if (token_len != 0)
      {
        /*
          The value of the token parameter obtained using the getenv()
          system call, which does not guarantee that the memory pointed
          to by the returned pointer can be read in the long term (for
          example, after changing the values of the environment variables
          of the current process). Therefore, we need to copy the token
          value to the working buffer:
        */
        if (!(token = (char *) alloc(token_len + 1)))
        {
          return 1;
        }
        memcpy(token, token_env, token_len + 1);
        local_token = token;
      }
    }
    if (token_len == 0) {
      my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                      "The --onboardbase-key-management-token option value "
                      "or the value of the corresponding parameter in the "
                      "configuration file must be specified, otherwise the "
                      "VAULT_TOKEN environment variable must be set",
                      0);
      return 1;
    }
  }
  else
  {
    /*
      If the VAULT_TOKEN environment variable is not set or
      is not equal to the value of the token parameter, then
      we must set (overwrite) it for correct operation of
      the mariabackup:
    */
    bool not_equal= token_env != NULL && strcmp(token_env, token) != 0;
    if (token_env == NULL || not_equal)
    {
#if defined(HAVE_SETENV) || !defined(_WIN32)
        setenv("VAULT_TOKEN", token, 1);
#else
        _putenv_s("VAULT_TOKEN", token);
#endif
      if (not_equal)
      {
        my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                        "The --onboardbase-key-management-token option value "
                        "or the value of the corresponding parameter is not "
                        "equal to the value of the VAULT_TOKEN environment "
                        "variable",
                        ME_ERROR_LOG_ONLY | ME_WARNING);
      }
    }
  }
#if ONBOARDBASE_DEBUG_LOGGING
  my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                  "plugin_init: token = %s, token_len = %d",
                  ME_ERROR_LOG_ONLY | ME_NOTE, token, (int) token_len);
#endif
  size_t buf_len = x_vault_token_len + token_len + 1;
  if (!(token_header = (char *) alloc(buf_len)))
  {
    return 1;
  }
  snprintf(token_header, buf_len, "%s%s", x_vault_token, token);
  /*
    In advance, we create a buffer containing the URL for vault
    + the "/data/" suffix (7 characters):
  */
  if (!(vault_url_data = (char *) alloc(vault_url_len + 7)))
  {
    return 1;
  }
  memcpy(vault_url_data, vault_url, vault_url_len);
  memcpy(vault_url_data + vault_url_len, "/data/", 7);
  /* Initialize curl: */
  CURLcode curl_res = curl_global_init(CURL_GLOBAL_ALL);
  if (curl_res != CURLE_OK)
  {
    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                    "unable to initialize curl library, "
                    "curl returned this error code: %u "
                    "with the following error message: %s",
                    0, curl_res, curl_easy_strerror(curl_res));
    return 1;
  }
  curl_inited = true;
  slist = curl_slist_append(slist, token_header);
  if (slist == NULL)
  {
    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                    "curl: unable to construct slist", 0);
    return 1;
  }
  /*
    If we do not need to check the key-value storage version,
    then we immediately return from this function:
  */
  if (check_kv_version == 0) {
    return 0;
  }
  /*
    Let's construct a URL to check the version of the key-value storage:
  */
  char *mount_url = (char *) alloc(vault_url_len + 11 + 6);
  if (mount_url == NULL)
  {
    my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                    "Memory allocation error", 0);
    return 1;
  }
  /*
    The prefix length must be recalculated, as it may have
    changed in the process of discarding trailing slashes:
  */
  prefix_len = vault_url_len - suffix_len;
  memcpy(mount_url, vault_url_data, prefix_len);
  memcpy(mount_url + prefix_len, "sys/mounts/", 11);
  memcpy(mount_url + prefix_len + 11, vault_url_data + prefix_len, suffix_len);
  memcpy(mount_url + prefix_len + 11 + suffix_len, "/tune", 6);
#if ONBOARDBASE_DEBUG_LOGGING
  my_printf_error(ER_UNKNOWN_ERROR, PLUGIN_ERROR_HEADER
                  "storage mount url: [%s]",
                  ME_ERROR_LOG_ONLY | ME_NOTE, mount_url);
#endif
  free(mount_url);
  return rc;
}

static int onboardbase_key_management_plugin_init(void *p)
{
  int rc = data.init();
  if (rc)
  {
    data.deinit();
  }
  return rc;
}

static int onboardbase_key_management_plugin_deinit(void *p)
{
  data.deinit();
  return 0;
}

/*
  Plugin library descriptor
*/
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
  0x0100 /* 1.0 */,
  NULL, /* status variables */
  settings,
  "1.0",
  MariaDB_PLUGIN_MATURITY_STABLE
}
maria_declare_plugin_end;