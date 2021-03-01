// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_STREAM_HPP
#define HTTPLIB_STREAM_HPP

#include <string>

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
  ssize_t write_format(const char *fmt, const Args &... args);
  ssize_t write(const char *ptr);
  ssize_t write(const std::string &s);
};

} // namespace httplib

#endif // HTTPLIB_STREAM_HPP
