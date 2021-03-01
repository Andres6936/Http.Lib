// Joan Andrés (@Andres6936) Github.

#include "Httplib/Response.hpp"

using namespace httplib;


// Response implementation
inline bool Response::has_header(const char *key) const {
  return headers.find(key) != headers.end();
}

inline std::string Response::get_header_value(const char *key,
    size_t id) const {
  return detail::get_header_value(headers, key, id, "");
}

template <typename T>
inline T Response::get_header_value(const char *key, size_t id) const {
  return detail::get_header_value<T>(headers, key, id, 0);
}

inline size_t Response::get_header_value_count(const char *key) const {
  auto r = headers.equal_range(key);
  return static_cast<size_t>(std::distance(r.first, r.second));
}

inline void Response::set_header(const char *key, const char *val) {
  if (!detail::has_crlf(key) && !detail::has_crlf(val)) {
    headers.emplace(key, val);
  }
}

inline void Response::set_header(const char *key, const std::string &val) {
  if (!detail::has_crlf(key) && !detail::has_crlf(val.c_str())) {
    headers.emplace(key, val);
  }
}

inline void Response::set_redirect(const char *url, int stat) {
  if (!detail::has_crlf(url)) {
    set_header("Location", url);
    if (300 <= stat && stat < 400) {
      this->status = stat;
    } else {
      this->status = 302;
    }
  }
}

inline void Response::set_redirect(const std::string &url, int stat) {
  set_redirect(url.c_str(), stat);
}

inline void Response::set_content(const char *s, size_t n,
    const char *content_type) {
  body.assign(s, n);

  auto rng = headers.equal_range("Content-Type");
  headers.erase(rng.first, rng.second);
  set_header("Content-Type", content_type);
}

inline void Response::set_content(const std::string &s,
    const char *content_type) {
  set_content(s.data(), s.size(), content_type);
}

inline void
Response::set_content_provider(size_t in_length, const char *content_type,
    ContentProvider provider,
    const std::function<void()> &resource_releaser) {
  assert(in_length > 0);
  set_header("Content-Type", content_type);
  content_length_ = in_length;
  content_provider_ = std::move(provider);
  content_provider_resource_releaser_ = resource_releaser;
  is_chunked_content_provider_ = false;
}

inline void
Response::set_content_provider(const char *content_type,
    ContentProviderWithoutLength provider,
    const std::function<void()> &resource_releaser) {
  set_header("Content-Type", content_type);
  content_length_ = 0;
  content_provider_ = detail::ContentProviderAdapter(std::move(provider));
  content_provider_resource_releaser_ = resource_releaser;
  is_chunked_content_provider_ = false;
}

inline void Response::set_chunked_content_provider(
    const char *content_type, ContentProviderWithoutLength provider,
    const std::function<void()> &resource_releaser) {
  set_header("Content-Type", content_type);
  content_length_ = 0;
  content_provider_ = detail::ContentProviderAdapter(std::move(provider));
  content_provider_resource_releaser_ = resource_releaser;
  is_chunked_content_provider_ = true;
}