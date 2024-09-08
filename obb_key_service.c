// obb_key_service.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <curl/curl.h>
#include "obb_key_service.h"

// Buffer to store response data
static char response_data[2048] = "";

// CURL write callback to store the key in a buffer
size_t write_callback(void *ptr, size_t size, size_t nmemb, void *userdata) {
    size_t total_size = size * nmemb;
    if (total_size < sizeof(response_data) - 1) {
        strncpy(response_data, (char *)ptr, total_size);
        response_data[total_size] = '\0';
    }
    return total_size;
}

// Function to parse the JSON response and extract the "value" field
void parse_json_response(char *secret_key, size_t secret_key_size) {
    char *value_start = strstr(response_data, "\"value\":\"");
    if (value_start) {
        value_start += 9; // Move past the `"value":"` part
        char *value_end = strchr(value_start, '"'); // Find the closing quote
        if (value_end) {
            size_t value_length = value_end - value_start;
            if (value_length < secret_key_size - 1) {
                strncpy(secret_key, value_start, value_length);
                secret_key[value_length] = '\0';
            }
        }
    }
}

// Function to fetch the secret key from the store server
int fetch_secret_key(const char *store_url, const char *api_key, const char *requested_key, char *secret_key, size_t secret_key_size) {
    CURL *curl;
    CURLcode res;
    struct curl_slist *headers = NULL;

    curl_global_init(CURL_GLOBAL_DEFAULT);
    curl = curl_easy_init();
    if (curl) {
        // Construct full URL by appending the key
        char full_url[1024];
        snprintf(full_url, sizeof(full_url), "%s?key=%s", store_url, requested_key);
        curl_easy_setopt(curl, CURLOPT_URL, full_url);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

        // Add the API key as a header if provided
        if (strlen(api_key) > 0) {
            char header[512];
            snprintf(header, sizeof(header), "store_key: %s", api_key);
            headers = curl_slist_append(headers, header);
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        }

        // Perform the request
        res = curl_easy_perform(curl);
        if (res != CURLE_OK) {
            fprintf(stderr, "CURL error: %s\n", curl_easy_strerror(res));
            curl_slist_free_all(headers);
            curl_easy_cleanup(curl);
            curl_global_cleanup();
            return 1;
        }

        // Parse the JSON response to extract the value
        parse_json_response(secret_key, secret_key_size);

        curl_slist_free_all(headers);
        curl_easy_cleanup(curl);
    }
    curl_global_cleanup();
    return 0;
}
