// Joan Andrés (@Andres6936) Github.

#include "Httplib/SSLServer.hpp"

using namespace httplib;


// SSL HTTP server implementation
inline SSLServer::SSLServer(const char *cert_path, const char *private_key_path,
    const char *client_ca_cert_file_path,
    const char *client_ca_cert_dir_path) {
  ctx_ = SSL_CTX_new(SSLv23_server_method());

  if (ctx_) {
    SSL_CTX_set_options(ctx_,
        SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
        SSL_OP_NO_COMPRESSION |
        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    // auto ecdh = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
    // SSL_CTX_set_tmp_ecdh(ctx_, ecdh);
    // EC_KEY_free(ecdh);

    if (SSL_CTX_use_certificate_chain_file(ctx_, cert_path) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx_, private_key_path, SSL_FILETYPE_PEM) !=
        1) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    } else if (client_ca_cert_file_path || client_ca_cert_dir_path) {
      // if (client_ca_cert_file_path) {
      //   auto list = SSL_load_client_CA_file(client_ca_cert_file_path);
      //   SSL_CTX_set_client_CA_list(ctx_, list);
      // }

      SSL_CTX_load_verify_locations(ctx_, client_ca_cert_file_path,
          client_ca_cert_dir_path);

      SSL_CTX_set_verify(
          ctx_,
          SSL_VERIFY_PEER |
          SSL_VERIFY_FAIL_IF_NO_PEER_CERT, // SSL_VERIFY_CLIENT_ONCE,
          nullptr);
    }
  }
}

inline SSLServer::SSLServer(X509 *cert, EVP_PKEY *private_key,
    X509_STORE *client_ca_cert_store) {
  ctx_ = SSL_CTX_new(SSLv23_server_method());

  if (ctx_) {
    SSL_CTX_set_options(ctx_,
        SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
        SSL_OP_NO_COMPRESSION |
        SSL_OP_NO_SESSION_RESUMPTION_ON_RENEGOTIATION);

    if (SSL_CTX_use_certificate(ctx_, cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx_, private_key) != 1) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    } else if (client_ca_cert_store) {

      SSL_CTX_set_cert_store(ctx_, client_ca_cert_store);

      SSL_CTX_set_verify(
          ctx_,
          SSL_VERIFY_PEER |
          SSL_VERIFY_FAIL_IF_NO_PEER_CERT, // SSL_VERIFY_CLIENT_ONCE,
          nullptr);
    }
  }
}

inline SSLServer::~SSLServer() {
  if (ctx_) { SSL_CTX_free(ctx_); }
}

inline bool SSLServer::is_valid() const { return ctx_; }

inline bool SSLServer::process_and_close_socket(socket_t sock) {
  auto ssl = detail::ssl_new(
      sock, ctx_, ctx_mutex_,
      [&](SSL *ssl) {
        return detail::ssl_connect_or_accept_nonblocking(
            sock, ssl, SSL_accept, read_timeout_sec_, read_timeout_usec_);
      },
      [](SSL * /*ssl*/) { return true; });

  bool ret = false;
  if (ssl) {
    ret = detail::process_server_socket_ssl(
        ssl, sock, keep_alive_max_count_, keep_alive_timeout_sec_,
        read_timeout_sec_, read_timeout_usec_, write_timeout_sec_,
        write_timeout_usec_,
        [this, ssl](Stream &strm, bool close_connection,
            bool &connection_closed) {
          return process_request(strm, close_connection, connection_closed,
              [&](Request &req) { req.ssl = ssl; });
        });

    // Shutdown gracefully if the result seemed successful, non-gracefully if
    // the connection appeared to be closed.
    const bool shutdown_gracefully = ret;
    detail::ssl_delete(ctx_mutex_, ssl, shutdown_gracefully);
  }

  detail::shutdown_socket(sock);
  detail::close_socket(sock);
  return ret;
}