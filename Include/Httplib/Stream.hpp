// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_STREAM_HPP
#define HTTPLIB_STREAM_HPP

#include <array>
#include <string>
#include <vector>

#include <Httplib/Using/SocketType.hpp>

namespace httplib {

class Stream {
public:
  virtual ~Stream() = default;

  virtual bool is_readable() const = 0;
  virtual bool is_writable() const = 0;

  virtual ssize_t read(char *ptr, size_t size) = 0;
  virtual ssize_t write(const char *ptr, size_t size) = 0;
  virtual void get_remote_ip_and_port(std::string &ip, int &port) const = 0;
  virtual socket_t socket() const = 0;

  template <typename... Args>
  ssize_t write_format(const char *fmt, const Args &... args)
  {
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

  ssize_t write(const char *ptr);
  ssize_t write(const std::string &s);
};

namespace detail {

inline bool write_data(Stream &strm, const char *d, size_t l) {
  size_t offset = 0;
  while (offset < l) {
    auto length = strm.write(d + offset, l - offset);
    if (length < 0) { return false; }
    offset += static_cast<size_t>(length);
  }
  return true;
}


}


} // namespace httplib

#endif // HTTPLIB_STREAM_HPP
