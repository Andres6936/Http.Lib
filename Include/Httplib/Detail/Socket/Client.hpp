// Joan Andrés (@Andres6936) Github.

#pragma once

#include <Httplib/SocketStream.hpp>

namespace httplib {

namespace detail {

template <typename T>
inline bool process_client_socket(socket_t sock, time_t read_timeout_sec,
    time_t read_timeout_usec,
    time_t write_timeout_sec,
    time_t write_timeout_usec, T callback) {
  SocketStream strm(sock, read_timeout_sec, read_timeout_usec,
      write_timeout_sec, write_timeout_usec);
  return callback(strm);
}


inline socket_t create_client_socket(const char *host, int port,
    bool tcp_nodelay,
    SocketOptions socket_options,
    time_t timeout_sec, time_t timeout_usec,
    const std::string &intf, Error &error) {
  auto sock = create_socket(
      host, port, 0, tcp_nodelay, std::move(socket_options),
      [&](socket_t sock, struct addrinfo &ai) -> bool {
        if (!intf.empty()) {
#ifdef USE_IF2IP
          auto ip = if2ip(intf);
          if (ip.empty()) { ip = intf; }
          if (!bind_ip_address(sock, ip.c_str())) {
            error = Error::BindIPAddress;
            return false;
          }
#endif
        }

        set_nonblocking(sock, true);

        auto ret =
            ::connect(sock, ai.ai_addr, static_cast<socklen_t>(ai.ai_addrlen));

        if (ret < 0) {
          if (is_connection_error() ||
              !wait_until_socket_is_ready(sock, timeout_sec, timeout_usec)) {
            close_socket(sock);
            error = Error::Connection;
            return false;
          }
        }

        set_nonblocking(sock, false);
        error = Error::Success;
        return true;
      });

  if (sock != INVALID_SOCKET) {
    error = Error::Success;
  } else {
    if (error == Error::Success) { error = Error::Connection; }
  }

  return sock;
}


}

} // namespace httplib
