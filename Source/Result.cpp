// Joan Andrés (@Andres6936) Github.

#include "Httplib/Result.hpp"
#include <Httplib/Detail/Header.hpp>

using namespace httplib;


// Result implementation
inline bool Result::has_request_header(const char *key) const {
  return request_headers_.find(key) != request_headers_.end();
}

inline std::string Result::get_request_header_value(const char *key,
    size_t id) const {
  return detail::get_header_value(request_headers_, key, id, "");
}

template <typename T>
inline T Result::get_request_header_value(const char *key, size_t id) const {
  return detail::get_header_value<T>(request_headers_, key, id, 0);
}

inline size_t Result::get_request_header_value_count(const char *key) const {
  auto r = request_headers_.equal_range(key);
  return static_cast<size_t>(std::distance(r.first, r.second));
}