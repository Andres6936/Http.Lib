// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_SSLSOCKETSTREAM_HPP
#define HTTPLIB_SSLSOCKETSTREAM_HPP

namespace httplib {

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
class SSLSocketStream : public Stream {
public:
  SSLSocketStream(socket_t sock, SSL *ssl, time_t read_timeout_sec,
      time_t read_timeout_usec, time_t write_timeout_sec,
      time_t write_timeout_usec);
  ~SSLSocketStream() override;

  bool is_readable() const override;
  bool is_writable() const override;
  ssize_t read(char *ptr, size_t size) override;
  ssize_t write(const char *ptr, size_t size) override;
  void get_remote_ip_and_port(std::string &ip, int &port) const override;
  socket_t socket() const override;

private:
  socket_t sock_;
  SSL *ssl_;
  time_t read_timeout_sec_;
  time_t read_timeout_usec_;
  time_t write_timeout_sec_;
  time_t write_timeout_usec_;
};
#endif

} // namespace httplib

#endif // HTTPLIB_SSLSOCKETSTREAM_HPP
