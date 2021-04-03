// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_STRING_HPP
#define HTTPLIB_STRING_HPP

namespace httplib {

namespace detail {

inline bool has_crlf(const char *s) {
  auto p = s;
  while (*p) {
    if (*p == '\r' || *p == '\n') { return true; }
    p++;
  }
  return false;
}

}

} // namespace httplib

#endif // HTTPLIB_STRING_HPP
