// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_AUTHENTICATION_HPP
#define HTTPLIB_AUTHENTICATION_HPP

#include <string>
#include <utility>

#include <Httplib/ZLib/Base64.hpp>

namespace httplib {

inline std::pair<std::string, std::string>
make_basic_authentication_header(const std::string &username,
    const std::string &password,
    bool is_proxy = false) {
  auto field = "Basic " + detail::base64_encode(username + ":" + password);
  auto key = is_proxy ? "Proxy-Authorization" : "Authorization";
  return std::make_pair(key, std::move(field));
}

inline std::pair<std::string, std::string>
make_bearer_token_authentication_header(const std::string &token,
    bool is_proxy = false) {
  auto field = "Bearer " + token;
  auto key = is_proxy ? "Proxy-Authorization" : "Authorization";
  return std::make_pair(key, std::move(field));
}

} // namespace httplib

#endif // HTTPLIB_AUTHENTICATION_HPP
