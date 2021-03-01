// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_HEADERS_HPP
#define HTTPLIB_HEADERS_HPP

#include <map>

namespace httplib {

namespace detail {
struct ci {
  bool operator()(const std::string &s1, const std::string &s2) const {
    return std::lexicographical_compare(s1.begin(), s1.end(), s2.begin(),
                                        s2.end(),
                                        [](unsigned char c1, unsigned char c2) {
                                          return ::tolower(c1) < ::tolower(c2);
                                        });
  }
};
}

using Headers = std::multimap<std::string, std::string, detail::ci>;

} // namespace httplib

#endif // HTTPLIB_HEADERS_HPP
