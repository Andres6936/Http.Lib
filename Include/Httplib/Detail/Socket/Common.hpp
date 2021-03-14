// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_COMMON_HPP
#define HTTPLIB_COMMON_HPP

namespace httplib {


namespace detail {


inline int shutdown_socket(socket_t sock) {
#ifdef _WIN32
  return shutdown(sock, SD_BOTH);
#else
  return shutdown(sock, SHUT_RDWR);
#endif
}

template <typename BindOrConnect>
socket_t create_socket(const char *host, int port, int socket_flags,
    bool tcp_nodelay, SocketOptions socket_options,
    BindOrConnect bind_or_connect) {
  // Get address info
  struct addrinfo hints;
  struct addrinfo *result;

  memset(&hints, 0, sizeof(struct addrinfo));
  hints.ai_family = AF_UNSPEC;
  hints.ai_socktype = SOCK_STREAM;
  hints.ai_flags = socket_flags;
  hints.ai_protocol = 0;

  auto service = std::to_string(port);

  if (getaddrinfo(host, service.c_str(), &hints, &result)) {
#ifdef __linux__
    res_init();
#endif
    return INVALID_SOCKET;
  }

  for (auto rp = result; rp; rp = rp->ai_next) {
    // Create a socket
#ifdef _WIN32
    auto sock = WSASocketW(rp->ai_family, rp->ai_socktype, rp->ai_protocol,
                           nullptr, 0, WSA_FLAG_NO_HANDLE_INHERIT);
    /**
     * Since the WSA_FLAG_NO_HANDLE_INHERIT is only supported on Windows 7 SP1
     * and above the socket creation fails on older Windows Systems.
     *
     * Let's try to create a socket the old way in this case.
     *
     * Reference:
     * https://docs.microsoft.com/en-us/windows/win32/api/winsock2/nf-winsock2-wsasocketa
     *
     * WSA_FLAG_NO_HANDLE_INHERIT:
     * This flag is supported on Windows 7 with SP1, Windows Server 2008 R2 with
     * SP1, and later
     *
     */
    if (sock == INVALID_SOCKET) {
      sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
    }
#else
    auto sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
#endif
    if (sock == INVALID_SOCKET) { continue; }

#ifndef _WIN32
    if (fcntl(sock, F_SETFD, FD_CLOEXEC) == -1) { continue; }
#endif

    if (tcp_nodelay) {
      int yes = 1;
      setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, reinterpret_cast<char *>(&yes),
          sizeof(yes));
    }

    if (socket_options) { socket_options(sock); }

    if (rp->ai_family == AF_INET6) {
      int no = 0;
      setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, reinterpret_cast<char *>(&no),
          sizeof(no));
    }

    // bind or connect
    if (bind_or_connect(sock, *rp)) {
      freeaddrinfo(result);
      return sock;
    }

    close_socket(sock);
  }

  freeaddrinfo(result);
  return INVALID_SOCKET;
}


inline int close_socket(socket_t sock) {
#ifdef _WIN32
  return closesocket(sock);
#else
  return close(sock);
#endif
}

}

} // namespace httplib

#endif // HTTPLIB_COMMON_HPP
