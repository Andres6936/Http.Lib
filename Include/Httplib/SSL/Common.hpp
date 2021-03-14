// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_COMMON_HPP
#define HTTPLIB_COMMON_HPP

namespace httplib {

namespace detail {

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT


template <typename U, typename V>
inline SSL *ssl_new(socket_t sock, SSL_CTX *ctx, std::mutex &ctx_mutex,
    U SSL_connect_or_accept, V setup) {
  SSL *ssl = nullptr;
  {
    std::lock_guard<std::mutex> guard(ctx_mutex);
    ssl = SSL_new(ctx);
  }

  if (ssl) {
    set_nonblocking(sock, true);
    auto bio = BIO_new_socket(static_cast<int>(sock), BIO_NOCLOSE);
    BIO_set_nbio(bio, 1);
    SSL_set_bio(ssl, bio, bio);

    if (!setup(ssl) || SSL_connect_or_accept(ssl) != 1) {
      SSL_shutdown(ssl);
      {
        std::lock_guard<std::mutex> guard(ctx_mutex);
        SSL_free(ssl);
      }
      set_nonblocking(sock, false);
      return nullptr;
    }
    BIO_set_nbio(bio, 0);
    set_nonblocking(sock, false);
  }

  return ssl;
}

inline void ssl_delete(std::mutex &ctx_mutex, SSL *ssl,
    bool shutdown_gracefully) {
  // sometimes we may want to skip this to try to avoid SIGPIPE if we know
  // the remote has closed the network connection
  // Note that it is not always possible to avoid SIGPIPE, this is merely a
  // best-efforts.
  if (shutdown_gracefully) { SSL_shutdown(ssl); }

  std::lock_guard<std::mutex> guard(ctx_mutex);
  SSL_free(ssl);
}

template <typename U>
bool ssl_connect_or_accept_nonblocking(socket_t sock, SSL *ssl,
    U ssl_connect_or_accept,
    time_t timeout_sec,
    time_t timeout_usec) {
  int res = 0;
  while ((res = ssl_connect_or_accept(ssl)) != 1) {
    auto err = SSL_get_error(ssl, res);
    switch (err) {
    case SSL_ERROR_WANT_READ:
      if (select_read(sock, timeout_sec, timeout_usec) > 0) { continue; }
      break;
    case SSL_ERROR_WANT_WRITE:
      if (select_write(sock, timeout_sec, timeout_usec) > 0) { continue; }
      break;
    default: break;
    }
    return false;
  }
  return true;
}

template <typename T>
inline bool
process_server_socket_ssl(SSL *ssl, socket_t sock, size_t keep_alive_max_count,
    time_t keep_alive_timeout_sec,
    time_t read_timeout_sec, time_t read_timeout_usec,
    time_t write_timeout_sec, time_t write_timeout_usec,
    T callback) {
  return process_server_socket_core(
      sock, keep_alive_max_count, keep_alive_timeout_sec,
      [&](bool close_connection, bool &connection_closed) {
        SSLSocketStream strm(sock, ssl, read_timeout_sec, read_timeout_usec,
            write_timeout_sec, write_timeout_usec);
        return callback(strm, close_connection, connection_closed);
      });
}

template <typename T>
inline bool
process_client_socket_ssl(SSL *ssl, socket_t sock, time_t read_timeout_sec,
    time_t read_timeout_usec, time_t write_timeout_sec,
    time_t write_timeout_usec, T callback) {
  SSLSocketStream strm(sock, ssl, read_timeout_sec, read_timeout_usec,
      write_timeout_sec, write_timeout_usec);
  return callback(strm);
}

#endif

}

} // namespace httplib

#endif // HTTPLIB_COMMON_HPP
