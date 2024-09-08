// obb_key_service.h
#ifndef OBB_KEY_SERVICE_H
#define OBB_KEY_SERVICE_H

int fetch_secret_key(const char *store_url, const char *api_key, const char *requested_key, char *secret_key, size_t secret_key_size);

#endif // OBB_KEY_SERVICE_H
