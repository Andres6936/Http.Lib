// Joan Andrés (@Andres6936) Github.

#include "Httplib/Stream.hpp"

using namespace httplib;


// Stream implementation
inline ssize_t Stream::write(const char *ptr) {
  return write(ptr, strlen(ptr));
}

inline ssize_t Stream::write(const std::string &s) {
  return write(s.data(), s.size());
}

template <typename... Args>
inline ssize_t Stream::write_format(const char *fmt, const Args &... args) {
  const auto bufsiz = 2048;
  std::array<char, bufsiz> buf;

#if defined(_MSC_VER) && _MSC_VER < 1900
  auto sn = _snprintf_s(buf.data(), bufsiz - 1, buf.size() - 1, fmt, args...);
#else
  auto sn = snprintf(buf.data(), buf.size() - 1, fmt, args...);
#endif
  if (sn <= 0) { return sn; }

  auto n = static_cast<size_t>(sn);

  if (n >= buf.size() - 1) {
    std::vector<char> glowable_buf(buf.size());

    while (n >= glowable_buf.size() - 1) {
      glowable_buf.resize(glowable_buf.size() * 2);
#if defined(_MSC_VER) && _MSC_VER < 1900
      n = static_cast<size_t>(_snprintf_s(&glowable_buf[0], glowable_buf.size(),
                                          glowable_buf.size() - 1, fmt,
                                          args...));
#else
      n = static_cast<size_t>(
          snprintf(&glowable_buf[0], glowable_buf.size() - 1, fmt, args...));
#endif
    }
    return write(&glowable_buf[0], n);
  } else {
    return write(buf.data(), n);
  }
}