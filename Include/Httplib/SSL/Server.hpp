// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_SSLSERVER_HPP
#define HTTPLIB_SSLSERVER_HPP

namespace httplib {


#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
class SSLServer : public Server {
public:
  SSLServer(const char *cert_path, const char *private_key_path,
      const char *client_ca_cert_file_path = nullptr,
      const char *client_ca_cert_dir_path = nullptr);

  SSLServer(X509 *cert, EVP_PKEY *private_key,
      X509_STORE *client_ca_cert_store = nullptr);

  ~SSLServer() override;

  bool is_valid() const override;

private:
  bool process_and_close_socket(socket_t sock) override;

  SSL_CTX *ctx_;
  std::mutex ctx_mutex_;
};

#endif

}


#endif // HTTPLIB_SSLSERVER_HPP
