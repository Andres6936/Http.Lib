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


inline bool parse_www_authenticate(const Response &res,
    std::map<std::string, std::string> &auth,
    bool is_proxy) {
  auto auth_key = is_proxy ? "Proxy-Authenticate" : "WWW-Authenticate";
  if (res.has_header(auth_key)) {
    static auto re = std::regex(R"~((?:(?:,\s*)?(.+?)=(?:"(.*?)"|([^,]*))))~");
    auto s = res.get_header_value(auth_key);
    auto pos = s.find(' ');
    if (pos != std::string::npos) {
      auto type = s.substr(0, pos);
      if (type == "Basic") {
        return false;
      } else if (type == "Digest") {
        s = s.substr(pos + 1);
        auto beg = std::sregex_iterator(s.begin(), s.end(), re);
        for (auto i = beg; i != std::sregex_iterator(); ++i) {
          auto m = *i;
          auto key = s.substr(static_cast<size_t>(m.position(1)),
              static_cast<size_t>(m.length(1)));
          auto val = m.length(2) > 0
                     ? s.substr(static_cast<size_t>(m.position(2)),
                  static_cast<size_t>(m.length(2)))
                     : s.substr(static_cast<size_t>(m.position(3)),
                  static_cast<size_t>(m.length(3)));
          auth[key] = val;
        }
        return true;
      }
    }
  }
  return false;
}

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline std::pair<std::string, std::string> make_digest_authentication_header(
    const Request &req, const std::map<std::string, std::string> &auth,
    size_t cnonce_count, const std::string &cnonce, const std::string &username,
    const std::string &password, bool is_proxy = false) {
  using namespace std;

  string nc;
  {
    stringstream ss;
    ss << setfill('0') << setw(8) << hex << cnonce_count;
    nc = ss.str();
  }

  auto qop = auth.at("qop");
  if (qop.find("auth-int") != std::string::npos) {
    qop = "auth-int";
  } else {
    qop = "auth";
  }

  std::string algo = "MD5";
  if (auth.find("algorithm") != auth.end()) { algo = auth.at("algorithm"); }

  string response;
  {
    auto H = algo == "SHA-256"
                 ? detail::SHA_256
                 : algo == "SHA-512" ? detail::SHA_512 : detail::MD5;

    auto A1 = username + ":" + auth.at("realm") + ":" + password;

    auto A2 = req.method + ":" + req.path;
    if (qop == "auth-int") { A2 += ":" + H(req.body); }

    response = H(H(A1) + ":" + auth.at("nonce") + ":" + nc + ":" + cnonce +
                 ":" + qop + ":" + H(A2));
  }

  auto field = "Digest username=\"" + username + "\", realm=\"" +
               auth.at("realm") + "\", nonce=\"" + auth.at("nonce") +
               "\", uri=\"" + req.path + "\", algorithm=" + algo +
               ", qop=" + qop + ", nc=\"" + nc + "\", cnonce=\"" + cnonce +
               "\", response=\"" + response + "\"";

  auto key = is_proxy ? "Proxy-Authorization" : "Authorization";
  return std::make_pair(key, field);
}
#endif

} // namespace httplib

#endif // HTTPLIB_AUTHENTICATION_HPP
