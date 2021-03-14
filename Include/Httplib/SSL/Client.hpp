// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_CLIENT_HPP
#define HTTPLIB_CLIENT_HPP

namespace httplib {

namespace detail {

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

class SSLClient : public ClientImpl {
public:
  explicit SSLClient(const std::string &host);

  explicit SSLClient(const std::string &host, int port);

  explicit SSLClient(const std::string &host, int port,
      const std::string &client_cert_path,
      const std::string &client_key_path);

  explicit SSLClient(const std::string &host, int port, X509 *client_cert,
      EVP_PKEY *client_key);

  ~SSLClient() override;

  bool is_valid() const override;

  void set_ca_cert_path(const char *ca_cert_file_path,
      const char *ca_cert_dir_path = nullptr);

  void set_ca_cert_store(X509_STORE *ca_cert_store);

  long get_openssl_verify_result() const;

  SSL_CTX *ssl_context() const;

private:
  bool create_and_connect_socket(Socket &socket, Error &error) override;
  void shutdown_ssl(Socket &socket, bool shutdown_gracefully) override;

  bool process_socket(const Socket &socket,
      std::function<bool(Stream &strm)> callback) override;
  bool is_ssl() const override;

  bool connect_with_proxy(Socket &sock, Response &res, bool &success,
      Error &error);
  bool initialize_ssl(Socket &socket, Error &error);

  bool load_certs();

  bool verify_host(X509 *server_cert) const;
  bool verify_host_with_subject_alt_name(X509 *server_cert) const;
  bool verify_host_with_common_name(X509 *server_cert) const;
  bool check_host_name(const char *pattern, size_t pattern_len) const;

  SSL_CTX *ctx_;
  std::mutex ctx_mutex_;
  std::once_flag initialize_cert_;

  std::vector<std::string> host_components_;

  std::string ca_cert_file_path_;
  std::string ca_cert_dir_path_;
  long verify_result_ = 0;

  friend class ClientImpl;
};

#endif

}

} // namespace httplib

#endif // HTTPLIB_CLIENT_HPP
