// Joan Andrés (@Andres6936) Github.

#include "Httplib/Request.hpp"
#include <Httplib/Util/String.hpp>
#include <Httplib/Detail/Header.hpp>

using namespace httplib;


// Request implementation
bool Request::has_header(const char *key) const {
  return detail::has_header(headers, key);
}

std::string Request::get_header_value(const char *key, size_t id) const {
  return detail::get_header_value(headers, key, id, "");
}

template <typename T>
T Request::get_header_value(const char *key, size_t id) const {
  return detail::get_header_value<T>(headers, key, id, 0);
}

size_t Request::get_header_value_count(const char *key) const {
  auto r = headers.equal_range(key);
  return static_cast<size_t>(std::distance(r.first, r.second));
}

void Request::set_header(const char *key, const char *val) {
  if (!detail::has_crlf(key) && !detail::has_crlf(val)) {
    headers.emplace(key, val);
  }
}

void Request::set_header(const char *key, const std::string &val) {
  if (!detail::has_crlf(key) && !detail::has_crlf(val.c_str())) {
    headers.emplace(key, val);
  }
}

bool Request::has_param(const char *key) const {
  return params.find(key) != params.end();
}

std::string Request::get_param_value(const char *key, size_t id) const {
  auto rng = params.equal_range(key);
  auto it = rng.first;
  std::advance(it, static_cast<ssize_t>(id));
  if (it != rng.second) { return it->second; }
  return std::string();
}

size_t Request::get_param_value_count(const char *key) const {
  auto r = params.equal_range(key);
  return static_cast<size_t>(std::distance(r.first, r.second));
}

bool Request::is_multipart_form_data() const {
  const auto &content_type = get_header_value("Content-Type");
  return !content_type.find("multipart/form-data");
}

bool Request::has_file(const char *key) const {
  return files.find(key) != files.end();
}

MultipartFormData Request::get_file_value(const char *key) const {
  auto it = files.find(key);
  if (it != files.end()) { return it->second; }
  return MultipartFormData();
}