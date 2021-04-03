// Joan Andrés (@Andres6936) Github.

#pragma once

namespace httplib {

namespace detail {


template <typename T>
inline bool
process_server_socket_core(socket_t sock, size_t keep_alive_max_count,
    time_t keep_alive_timeout_sec, T callback) {
  assert(keep_alive_max_count > 0);
  auto ret = false;
  auto count = keep_alive_max_count;
  while (count > 0 && keep_alive(sock, keep_alive_timeout_sec)) {
    auto close_connection = count == 1;
    auto connection_closed = false;
    ret = callback(close_connection, connection_closed);
    if (!ret || connection_closed) { break; }
    count--;
  }
  return ret;
}

template <typename T>
inline bool
process_server_socket(socket_t sock, size_t keep_alive_max_count,
    time_t keep_alive_timeout_sec, time_t read_timeout_sec,
    time_t read_timeout_usec, time_t write_timeout_sec,
    time_t write_timeout_usec, T callback) {
  return process_server_socket_core(
      sock, keep_alive_max_count, keep_alive_timeout_sec,
      [&](bool close_connection, bool &connection_closed) {
        SocketStream strm(sock, read_timeout_sec, read_timeout_usec,
            write_timeout_sec, write_timeout_usec);
        return callback(strm, close_connection, connection_closed);
      });
}

}

} // namespace httplib

