// Joan Andrés (@Andres6936) Github.

#include "Httplib/SSL/SocketStream.hpp"

using namespace httplib;
using namespace detail;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

// SSL socket stream implementation
SSLSocketStream::SSLSocketStream(socket_t sock, SSL *ssl,
    time_t read_timeout_sec,
    time_t read_timeout_usec,
    time_t write_timeout_sec,
    time_t write_timeout_usec)
    : sock_(sock), ssl_(ssl), read_timeout_sec_(read_timeout_sec),
      read_timeout_usec_(read_timeout_usec),
      write_timeout_sec_(write_timeout_sec),
      write_timeout_usec_(write_timeout_usec) {
  SSL_clear_mode(ssl, SSL_MODE_AUTO_RETRY);
}

SSLSocketStream::~SSLSocketStream() {}

bool SSLSocketStream::is_readable() const {
  return detail::select_read(sock_, read_timeout_sec_, read_timeout_usec_) > 0;
}

bool SSLSocketStream::is_writable() const {
  return detail::select_write(sock_, write_timeout_sec_, write_timeout_usec_) >
         0;
}

ssize_t SSLSocketStream::read(char *ptr, size_t size) {
  if (SSL_pending(ssl_) > 0) {
    return SSL_read(ssl_, ptr, static_cast<int>(size));
  } else if (is_readable()) {
    auto ret = SSL_read(ssl_, ptr, static_cast<int>(size));
    if (ret < 0) {
      auto err = SSL_get_error(ssl_, ret);
      while (err == SSL_ERROR_WANT_READ) {
        if (SSL_pending(ssl_) > 0) {
          return SSL_read(ssl_, ptr, static_cast<int>(size));
        } else if (is_readable()) {
          ret = SSL_read(ssl_, ptr, static_cast<int>(size));
          if (ret >= 0) { return ret; }
          err = SSL_get_error(ssl_, ret);
        } else {
          return -1;
        }
      }
    }
    return ret;
  }
  return -1;
}

ssize_t SSLSocketStream::write(const char *ptr, size_t size) {
  if (is_writable()) { return SSL_write(ssl_, ptr, static_cast<int>(size)); }
  return -1;
}

void SSLSocketStream::get_remote_ip_and_port(std::string &ip,
    int &port) const {
  detail::get_remote_ip_and_port(sock_, ip, port);
}

socket_t SSLSocketStream::socket() const { return sock_; }

#endif