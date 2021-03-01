// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_RESPONSE_HPP
#define HTTPLIB_RESPONSE_HPP

#include <functional>

namespace httplib {


struct Response {
  std::string version;
  int status = -1;
  std::string reason;
  Headers headers;
  std::string body;
  std::string location; // Redirect location

  bool has_header(const char *key) const;
  std::string get_header_value(const char *key, size_t id = 0) const;
  template <typename T>
  T get_header_value(const char *key, size_t id = 0) const;
  size_t get_header_value_count(const char *key) const;
  void set_header(const char *key, const char *val);
  void set_header(const char *key, const std::string &val);

  void set_redirect(const char *url, int status = 302);
  void set_redirect(const std::string &url, int status = 302);
  void set_content(const char *s, size_t n, const char *content_type);
  void set_content(const std::string &s, const char *content_type);

  void set_content_provider(
      size_t length, const char *content_type, ContentProvider provider,
      const std::function<void()> &resource_releaser = nullptr);

  void set_content_provider(
      const char *content_type, ContentProviderWithoutLength provider,
      const std::function<void()> &resource_releaser = nullptr);

  void set_chunked_content_provider(
      const char *content_type, ContentProviderWithoutLength provider,
      const std::function<void()> &resource_releaser = nullptr);

  Response() = default;
  Response(const Response &) = default;
  Response &operator=(const Response &) = default;
  Response(Response &&) = default;
  Response &operator=(Response &&) = default;
  ~Response() {
    if (content_provider_resource_releaser_) {
      content_provider_resource_releaser_();
    }
  }

  // private members...
  size_t content_length_ = 0;
  ContentProvider content_provider_;
  std::function<void()> content_provider_resource_releaser_;
  bool is_chunked_content_provider_ = false;
};

using ResponseHandler = std::function<bool(const Response &response)>;

} // namespace httplib

#endif // HTTPLIB_RESPONSE_HPP
