// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_SOCKETSTREAM_HPP
#define HTTPLIB_SOCKETSTREAM_HPP

#include <string>

#include <Httplib/Stream.hpp>
#include <Httplib/Using/SocketType.hpp>

namespace httplib {


class SocketStream : public Stream {
public:
  SocketStream(socket_t sock, time_t read_timeout_sec, time_t read_timeout_usec,
      time_t write_timeout_sec, time_t write_timeout_usec);
  ~SocketStream() override;

  bool is_readable() const override;
  bool is_writable() const override;
  ssize_t read(char *ptr, size_t size) override;
  ssize_t write(const char *ptr, size_t size) override;
  void get_remote_ip_and_port(std::string &ip, int &port) const override;
  socket_t socket() const override;

private:
  socket_t sock_;
  time_t read_timeout_sec_;
  time_t read_timeout_usec_;
  time_t write_timeout_sec_;
  time_t write_timeout_usec_;
};

} // namespace httplib

#endif // HTTPLIB_SOCKETSTREAM_HPP
