// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_QUERY_HPP
#define HTTPLIB_QUERY_HPP

#include <Httplib/Util/Encode.hpp>

namespace httplib {

namespace detail {

inline std::string params_to_query_str(const Params &params) {
  std::string query;

  for (auto it = params.begin(); it != params.end(); ++it) {
    if (it != params.begin()) { query += "&"; }
    query += it->first;
    query += "=";
    query += encode_query_param(it->second);
  }
  return query;
}

inline std::string append_query_params(const char *path, const Params &params) {
  std::string path_with_query = path;
  const static std::regex re("[^?]+\\?.*");
  auto delm = std::regex_match(path, re) ? '&' : '?';
  path_with_query += delm + params_to_query_str(params);
  return path_with_query;
}

inline void parse_query_text(const std::string &s, Params &params) {
  split(s.data(), s.data() + s.size(), '&', [&](const char *b, const char *e) {
    std::string key;
    std::string val;
    split(b, e, '=', [&](const char *b2, const char *e2) {
      if (key.empty()) {
        key.assign(b2, e2);
      } else {
        val.assign(b2, e2);
      }
    });

    if (!key.empty()) {
      params.emplace(decode_url(key, true), decode_url(val, true));
    }
  });
}

}

} // namespace httplib

#endif // HTTPLIB_QUERY_HPP
