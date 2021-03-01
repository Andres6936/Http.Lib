// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_CLIENTIMPL_HPP
#define HTTPLIB_CLIENTIMPL_HPP

#include <string>
#include <thread>

#include <Httplib/Stream.hpp>
#include <Httplib/Result.hpp>
#include <Httplib/Request.hpp>
#include <Httplib/Headers.hpp>
#include <Httplib/Response.hpp>
#include <Httplib/Using/Logger.hpp>
#include <Httplib/Using/Params.hpp>
#include <Httplib/Using/Progress.hpp>
#include <Httplib/Using/ContentReceiver.hpp>

namespace httplib {


class ClientImpl {
public:
  explicit ClientImpl(const std::string &host);

  explicit ClientImpl(const std::string &host, int port);

  explicit ClientImpl(const std::string &host, int port,
      const std::string &client_cert_path,
      const std::string &client_key_path);

  virtual ~ClientImpl();

  virtual bool is_valid() const;

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
  Result Get(const char *path, ResponseHandler response_handler,
      ContentReceiver content_receiver, Progress progress);
  Result Get(const char *path, const Headers &headers,
      ResponseHandler response_handler, ContentReceiver content_receiver,
      Progress progress);

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

protected:
  struct Socket {
    socket_t sock = INVALID_SOCKET;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    SSL *ssl = nullptr;
#endif

    bool is_open() const { return sock != INVALID_SOCKET; }
  };

  Result send_(Request &&req);

  virtual bool create_and_connect_socket(Socket &socket, Error &error);

  // All of:
  //   shutdown_ssl
  //   shutdown_socket
  //   close_socket
  // should ONLY be called when socket_mutex_ is locked.
  // Also, shutdown_ssl and close_socket should also NOT be called concurrently
  // with a DIFFERENT thread sending requests using that socket.
  virtual void shutdown_ssl(Socket &socket, bool shutdown_gracefully);
  void shutdown_socket(Socket &socket);
  void close_socket(Socket &socket);

  // Similar to shutdown_ssl and close_socket, this should NOT be called
  // concurrently with a DIFFERENT thread sending requests from the socket
  void lock_socket_and_shutdown_and_close();

  bool process_request(Stream &strm, Request &req, Response &res,
      bool close_connection, Error &error);

  bool write_content_with_provider(Stream &strm, const Request &req,
      Error &error);

  void copy_settings(const ClientImpl &rhs);

  // Socket endoint information
  const std::string host_;
  const int port_;
  const std::string host_and_port_;

  // Current open socket
  Socket socket_;
  mutable std::mutex socket_mutex_;
  std::recursive_mutex request_mutex_;

  // These are all protected under socket_mutex
  size_t socket_requests_in_flight_ = 0;
  std::thread::id socket_requests_are_from_thread_ = std::thread::id();
  bool socket_should_be_closed_when_request_is_done_ = false;

  // Default headers
  Headers default_headers_;

  // Settings
  std::string client_cert_path_;
  std::string client_key_path_;

  time_t connection_timeout_sec_ = CPPHTTPLIB_CONNECTION_TIMEOUT_SECOND;
  time_t connection_timeout_usec_ = CPPHTTPLIB_CONNECTION_TIMEOUT_USECOND;
  time_t read_timeout_sec_ = CPPHTTPLIB_READ_TIMEOUT_SECOND;
  time_t read_timeout_usec_ = CPPHTTPLIB_READ_TIMEOUT_USECOND;
  time_t write_timeout_sec_ = CPPHTTPLIB_WRITE_TIMEOUT_SECOND;
  time_t write_timeout_usec_ = CPPHTTPLIB_WRITE_TIMEOUT_USECOND;

  std::string basic_auth_username_;
  std::string basic_auth_password_;
  std::string bearer_token_auth_token_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  std::string digest_auth_username_;
  std::string digest_auth_password_;
#endif

  bool keep_alive_ = false;
  bool follow_location_ = false;

  bool tcp_nodelay_ = CPPHTTPLIB_TCP_NODELAY;
  SocketOptions socket_options_ = nullptr;

  bool compress_ = false;
  bool decompress_ = true;

  std::string interface_;

  std::string proxy_host_;
  int proxy_port_ = -1;

  std::string proxy_basic_auth_username_;
  std::string proxy_basic_auth_password_;
  std::string proxy_bearer_token_auth_token_;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  std::string proxy_digest_auth_username_;
  std::string proxy_digest_auth_password_;
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  bool server_certificate_verification_ = true;
#endif

  Logger logger_;

private:
  socket_t create_client_socket(Error &error) const;
  bool read_response_line(Stream &strm, const Request &req, Response &res);
  bool write_request(Stream &strm, Request &req, bool close_connection,
      Error &error);
  bool redirect(Request &req, Response &res, Error &error);
  bool handle_request(Stream &strm, Request &req, Response &res,
      bool close_connection, Error &error);
  std::unique_ptr<Response> send_with_content_provider(
      Request &req,
      // const char *method, const char *path, const Headers &headers,
      const char *body, size_t content_length, ContentProvider content_provider,
      ContentProviderWithoutLength content_provider_without_length,
      const char *content_type, Error &error);
  Result send_with_content_provider(
      const char *method, const char *path, const Headers &headers,
      const char *body, size_t content_length, ContentProvider content_provider,
      ContentProviderWithoutLength content_provider_without_length,
      const char *content_type);

  virtual bool process_socket(const Socket &socket,
      std::function<bool(Stream &strm)> callback);
  virtual bool is_ssl() const;
};
} // namespace httplib

#endif // HTTPLIB_CLIENTIMPL_HPP
