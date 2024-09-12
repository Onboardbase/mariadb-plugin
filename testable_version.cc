#include <string>
#include <sstream>
#include <curl/curl.h>
#include <iostream> // Include for std::cout and std::cerr
#define MAX_RESPONSE_SIZE 131072
// (write_response_memory, perform_with_retries remain the same)
#define JSV_OBJECT 1 // Placeholder, replace with actual definition from your JSON library
#define JSV_STRING 2
int json_get_object_key(const char* js, const char* end, const char *key, const char** result, int *len) {
    // Placeholder, implement or use a JSON library to extract key-value pairs
    *result = js; // Assuming the entire JSON is the object for simplicity
    *len = end - js;
    return JSV_OBJECT; // Placeholder, replace with actual return value
}
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

static int get_key_data (const char *js, int js_len,
                         const char **key, int *key_len,
                         const std::string &response_str)
{
  if (json_get_object_key(js, js + js_len, "data",
                          &js, &js_len) != JSV_OBJECT)
  {
    std::cerr << "Unable to get second-level data object "
                 "(http response is: " << response_str << ")" << std::endl;
    return 1;
  }

  // Extract the "value" field instead of "data"
  if (json_get_object_key(js, js + js_len, "value",
                          key, key_len) != JSV_STRING)
  {
    std::cerr << "Unable to get value string (http response is: " << response_str << ")" << std::endl;
    return 1;
  }
  return 0;
}

static CURLcode perform_with_retries(CURL *curl, std::ostringstream *read_data_stream, int max_retries = 3) {
  int retries = max_retries;
  CURLcode curl_res;
  do {
    curl_res = curl_easy_perform(curl);
    if (curl_res != CURLE_OPERATION_TIMEDOUT) {
      break;
    }
    read_data_stream->clear();
    read_data_stream->str("");
  } while (retries--);
  return curl_res;
}


// Simplified get_data function, only checks for "data" object
static int get_data(const std::string &response_str, const char **js, int *js_len) {
  const char *response = response_str.c_str();
  size_t response_len = response_str.size();

  if (response_len == 0) {
    return 1; // Indicate empty response (key not found)
  }

  if (json_get_object_key(response, response + response_len, "data", js, js_len) != JSV_OBJECT) {
    return 2; // Indicate error parsing JSON
  }
  return 0;
}

// get_key_data remains the same

std::string fetch_value_from_onboardbase(const std::string& url, const std::string& token) {
    CURL* curl = curl_easy_init();
    if (!curl) {
        std::cerr << "Error: Cannot initialize curl session." << std::endl;
        return "";
    }

    struct curl_slist* slist = NULL;
    std::string token_header = "store_key: " + token;
    slist = curl_slist_append(slist, token_header.c_str());

    std::ostringstream read_data_stream;
    curl_easy_setopt(curl, CURLOPT_URL, url.c_str());
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, slist);
    // Correctly set the write function
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_response_memory); 
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &read_data_stream);

    CURLcode res = perform_with_retries(curl, &read_data_stream);
    curl_slist_free_all(slist);
    curl_easy_cleanup(curl);

    if (res != CURLE_OK) {
        std::cerr << "Error: cURL request failed with code " << res << std::endl;
        return "";
    }

  std::string response_str = read_data_stream.str();
  const char *js;
  int js_len;

  if (get_data(response_str, &js, &js_len)) {
    std::cerr << "Error: JSON parsing error or empty response." << std::endl;
    return "";
  }

  const char *value_str;
  int value_len;
  if (get_key_data(js, js_len, &value_str, &value_len, response_str)) {
    return ""; 
  }

  return value_str; 
}


// Example usage:
int main() {
  std::string url = "https://public.onboardbase.com/api/v1/store/get/data";
  std::string token = "store_QNPC2X4Q7TQV4UH3YTJF";

  std::string value = fetch_value_from_onboardbase(url, token);

  if (!value.empty()) {
    std::cout << "Value from Onboardbase: " << value << std::endl;
  } else {
    std::cerr << "Error fetching value from Onboardbase." << std::endl;
  }

  return 0;
}