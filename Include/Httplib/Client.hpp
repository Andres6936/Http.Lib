// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_CLIENT_HPP
#define HTTPLIB_CLIENT_HPP

#include <string>
#include <memory>

#include <Httplib/Result.hpp>
#include <Httplib/Request.hpp>
#include <Httplib/Headers.hpp>
#include <Httplib/Response.hpp>
#include <Httplib/DataSink.hpp>
#include <Httplib/Using/Logger.hpp>
#include <Httplib/Using/Params.hpp>
#include <Httplib/Using/Progress.hpp>
#include <Httplib/Using/SocketOptions.hpp>
#include <Httplib/Using/ContentReceiver.hpp>

namespace httplib {

class ClientImpl;

class Client {
public:
  // Universal interface
  explicit Client(const char *scheme_host_port);

  explicit Client(const char *scheme_host_port,
      const std::string &client_cert_path,
      const std::string &client_key_path);

  // HTTP only interface
  explicit Client(const std::string &host, int port);

  explicit Client(const std::string &host, int port,
      const std::string &client_cert_path,
      const std::string &client_key_path);

  ~Client();

  bool is_valid() const;

  Result Get(const char *path);
  Result Get(const char *path, const Headers &headers);
  Result Get(const char *path, Progress progress);
  Result Get(const char *path, const Headers &headers, Progress progress);
  Result Get(const char *path, ContentReceiver content_receiver);
  Result Get(const char *path, const Headers &headers,
      ContentReceiver content_receiver);
  Result Get(const char *path, ContentReceiver content_receiver,
      Progress progress);
  Result Get(const char *path, const Headers &headers,
      ContentReceiver content_receiver, Progress progress);
  Result Get(const char *path, ResponseHandler response_handler,
      ContentReceiver content_receiver);
  Result Get(const char *path, const Headers &headers,
      ResponseHandler response_handler,
      ContentReceiver content_receiver);
  Result Get(const char *path, const Headers &headers,
      ResponseHandler response_handler, ContentReceiver content_receiver,
      Progress progress);
  Result Get(const char *path, ResponseHandler response_handler,
      ContentReceiver content_receiver, Progress progress);

  Result Get(const char *path, const Params &params, const Headers &headers,
      Progress progress = nullptr);
  Result Get(const char *path, const Params &params, const Headers &headers,
      ContentReceiver content_receiver, Progress progress = nullptr);
  Result Get(const char *path, const Params &params, const Headers &headers,
      ResponseHandler response_handler, ContentReceiver content_receiver,
      Progress progress = nullptr);

  Result Head(const char *path);
  Result Head(const char *path, const Headers &headers);

  Result Post(const char *path);
  Result Post(const char *path, const char *body, size_t content_length,
      const char *content_type);
  Result Post(const char *path, const Headers &headers, const char *body,
      size_t content_length, const char *content_type);
  Result Post(const char *path, const std::string &body,
      const char *content_type);
  Result Post(const char *path, const Headers &headers, const std::string &body,
      const char *content_type);
  Result Post(const char *path, size_t content_length,
      ContentProvider content_provider, const char *content_type);
  Result Post(const char *path, ContentProviderWithoutLength content_provider,
      const char *content_type);
  Result Post(const char *path, const Headers &headers, size_t content_length,
      ContentProvider content_provider, const char *content_type);
  Result Post(const char *path, const Headers &headers,
      ContentProviderWithoutLength content_provider,
      const char *content_type);
  Result Post(const char *path, const Params &params);
  Result Post(const char *path, const Headers &headers, const Params &params);
  Result Post(const char *path, const MultipartFormDataItems &items);
  Result Post(const char *path, const Headers &headers,
      const MultipartFormDataItems &items);
  Result Post(const char *path, const Headers &headers,
      const MultipartFormDataItems &items, const std::string &boundary);
  Result Put(const char *path);
  Result Put(const char *path, const char *body, size_t content_length,
      const char *content_type);
  Result Put(const char *path, const Headers &headers, const char *body,
      size_t content_length, const char *content_type);
  Result Put(const char *path, const std::string &body,
      const char *content_type);
  Result Put(const char *path, const Headers &headers, const std::string &body,
      const char *content_type);
  Result Put(const char *path, size_t content_length,
      ContentProvider content_provider, const char *content_type);
  Result Put(const char *path, ContentProviderWithoutLength content_provider,
      const char *content_type);
  Result Put(const char *path, const Headers &headers, size_t content_length,
      ContentProvider content_provider, const char *content_type);
  Result Put(const char *path, const Headers &headers,
      ContentProviderWithoutLength content_provider,
      const char *content_type);
  Result Put(const char *path, const Params &params);
  Result Put(const char *path, const Headers &headers, const Params &params);
  Result Patch(const char *path);
  Result Patch(const char *path, const char *body, size_t content_length,
      const char *content_type);
  Result Patch(const char *path, const Headers &headers, const char *body,
      size_t content_length, const char *content_type);
  Result Patch(const char *path, const std::string &body,
      const char *content_type);
  Result Patch(const char *path, const Headers &headers,
      const std::string &body, const char *content_type);
  Result Patch(const char *path, size_t content_length,
      ContentProvider content_provider, const char *content_type);
  Result Patch(const char *path, ContentProviderWithoutLength content_provider,
      const char *content_type);
  Result Patch(const char *path, const Headers &headers, size_t content_length,
      ContentProvider content_provider, const char *content_type);
  Result Patch(const char *path, const Headers &headers,
      ContentProviderWithoutLength content_provider,
      const char *content_type);

  Result Delete(const char *path);
  Result Delete(const char *path, const Headers &headers);
  Result Delete(const char *path, const char *body, size_t content_length,
      const char *content_type);
  Result Delete(const char *path, const Headers &headers, const char *body,
      size_t content_length, const char *content_type);
  Result Delete(const char *path, const std::string &body,
      const char *content_type);
  Result Delete(const char *path, const Headers &headers,
      const std::string &body, const char *content_type);

  Result Options(const char *path);
  Result Options(const char *path, const Headers &headers);

  bool send(Request &req, Response &res, Error &error);
  Result send(const Request &req);

  size_t is_socket_open() const;

  void stop();

  void set_default_headers(Headers headers);

  void set_tcp_nodelay(bool on);
  void set_socket_options(SocketOptions socket_options);

  void set_connection_timeout(time_t sec, time_t usec = 0);
  void set_read_timeout(time_t sec, time_t usec = 0);
  void set_write_timeout(time_t sec, time_t usec = 0);

  void set_basic_auth(const char *username, const char *password);
  void set_bearer_token_auth(const char *token);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_digest_auth(const char *username, const char *password);
#endif

  void set_keep_alive(bool on);
  void set_follow_location(bool on);

  void set_compress(bool on);

  void set_decompress(bool on);

  void set_interface(const char *intf);

  void set_proxy(const char *host, int port);
  void set_proxy_basic_auth(const char *username, const char *password);
  void set_proxy_bearer_token_auth(const char *token);
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_proxy_digest_auth(const char *username, const char *password);
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void enable_server_certificate_verification(bool enabled);
#endif

  void set_logger(Logger logger);

  // SSL
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  void set_ca_cert_path(const char *ca_cert_file_path,
      const char *ca_cert_dir_path = nullptr);

  void set_ca_cert_store(X509_STORE *ca_cert_store);

  long get_openssl_verify_result() const;

  SSL_CTX *ssl_context() const;
#endif

private:
  std::unique_ptr<ClientImpl> cli_;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  bool is_ssl_ = false;
#endif
};

} // namespace httplib

#endif // HTTPLIB_CLIENT_HPP
