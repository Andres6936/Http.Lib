// Joan Andrés (@Andres6936) Github.

#include "Httplib/SocketStream.hpp"

using namespace httplib;


// Socket stream implementation
inline SocketStream::SocketStream(socket_t sock, time_t read_timeout_sec,
    time_t read_timeout_usec,
    time_t write_timeout_sec,
    time_t write_timeout_usec)
    : sock_(sock), read_timeout_sec_(read_timeout_sec),
      read_timeout_usec_(read_timeout_usec),
      write_timeout_sec_(write_timeout_sec),
      write_timeout_usec_(write_timeout_usec) {}

inline SocketStream::~SocketStream() {}

inline bool SocketStream::is_readable() const {
  return select_read(sock_, read_timeout_sec_, read_timeout_usec_) > 0;
}

inline bool SocketStream::is_writable() const {
  return select_write(sock_, write_timeout_sec_, write_timeout_usec_) > 0;
}

inline ssize_t SocketStream::read(char *ptr, size_t size) {
  if (!is_readable()) { return -1; }

#ifdef _WIN32
  if (size > static_cast<size_t>((std::numeric_limits<int>::max)())) {
    return -1;
  }
  return recv(sock_, ptr, static_cast<int>(size), CPPHTTPLIB_RECV_FLAGS);
#else
  return handle_EINTR(
      [&]() { return recv(sock_, ptr, size, CPPHTTPLIB_RECV_FLAGS); });
#endif
}

inline ssize_t SocketStream::write(const char *ptr, size_t size) {
  if (!is_writable()) { return -1; }

#ifdef _WIN32
  if (size > static_cast<size_t>((std::numeric_limits<int>::max)())) {
    return -1;
  }
  return send(sock_, ptr, static_cast<int>(size), CPPHTTPLIB_SEND_FLAGS);
#else
  return handle_EINTR(
      [&]() { return send(sock_, ptr, size, CPPHTTPLIB_SEND_FLAGS); });
#endif
}

inline void SocketStream::get_remote_ip_and_port(std::string &ip,
    int &port) const {
  return detail::get_remote_ip_and_port(sock_, ip, port);
}

inline socket_t SocketStream::socket() const { return sock_; }