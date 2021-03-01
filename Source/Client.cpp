// Joan Andrés (@Andres6936) Github.

#include "Httplib/Client.hpp"
#include <Httplib/ClientImpl.hpp>
#include <Httplib/Detail/Memory.hpp>

using namespace httplib;

// Universal client implementation
inline Client::Client(const char *scheme_host_port)
    : Client(scheme_host_port, std::string(), std::string()) {}

inline Client::Client(const char *scheme_host_port,
    const std::string &client_cert_path,
    const std::string &client_key_path) {
  const static std::regex re(R"(^(?:([a-z]+)://)?([^:/?#]+)(?::(\d+))?)");

  std::cmatch m;
  if (std::regex_match(scheme_host_port, m, re)) {
    auto scheme = m[1].str();

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
    if (!scheme.empty() && (scheme != "http" && scheme != "https")) {
#else
      if (!scheme.empty() && scheme != "http") {
#endif
      std::string msg = "'" + scheme + "' scheme is not supported.";
      throw std::invalid_argument(msg);
      return;
    }

    auto is_ssl = scheme == "https";

    auto host = m[2].str();

    auto port_str = m[3].str();
    auto port = !port_str.empty() ? std::stoi(port_str) : (is_ssl ? 443 : 80);

    if (is_ssl) {
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
      cli_ = detail::make_unique<SSLClient>(host.c_str(), port,
          client_cert_path, client_key_path);
      is_ssl_ = is_ssl;
#endif
    } else {
      cli_ = detail::make_unique<ClientImpl>(host.c_str(), port,
          client_cert_path, client_key_path);
    }
  } else {
    cli_ = detail::make_unique<ClientImpl>(scheme_host_port, 80,
        client_cert_path, client_key_path);
  }
}

inline Client::Client(const std::string &host, int port)
    : cli_(detail::make_unique<ClientImpl>(host, port)) {}

inline Client::Client(const std::string &host, int port,
    const std::string &client_cert_path,
    const std::string &client_key_path)
    : cli_(detail::make_unique<ClientImpl>(host, port, client_cert_path,
    client_key_path)) {}

inline Client::~Client() {}

inline bool Client::is_valid() const {
  return cli_ != nullptr && cli_->is_valid();
}

inline Result Client::Get(const char *path) { return cli_->Get(path); }
inline Result Client::Get(const char *path, const Headers &headers) {
  return cli_->Get(path, headers);
}
inline Result Client::Get(const char *path, Progress progress) {
  return cli_->Get(path, std::move(progress));
}
inline Result Client::Get(const char *path, const Headers &headers,
    Progress progress) {
  return cli_->Get(path, headers, std::move(progress));
}
inline Result Client::Get(const char *path, ContentReceiver content_receiver) {
  return cli_->Get(path, std::move(content_receiver));
}
inline Result Client::Get(const char *path, const Headers &headers,
    ContentReceiver content_receiver) {
  return cli_->Get(path, headers, std::move(content_receiver));
}
inline Result Client::Get(const char *path, ContentReceiver content_receiver,
    Progress progress) {
  return cli_->Get(path, std::move(content_receiver), std::move(progress));
}
inline Result Client::Get(const char *path, const Headers &headers,
    ContentReceiver content_receiver, Progress progress) {
  return cli_->Get(path, headers, std::move(content_receiver),
      std::move(progress));
}
inline Result Client::Get(const char *path, ResponseHandler response_handler,
    ContentReceiver content_receiver) {
  return cli_->Get(path, std::move(response_handler),
      std::move(content_receiver));
}
inline Result Client::Get(const char *path, const Headers &headers,
    ResponseHandler response_handler,
    ContentReceiver content_receiver) {
  return cli_->Get(path, headers, std::move(response_handler),
      std::move(content_receiver));
}
inline Result Client::Get(const char *path, ResponseHandler response_handler,
    ContentReceiver content_receiver, Progress progress) {
  return cli_->Get(path, std::move(response_handler),
      std::move(content_receiver), std::move(progress));
}
inline Result Client::Get(const char *path, const Headers &headers,
    ResponseHandler response_handler,
    ContentReceiver content_receiver, Progress progress) {
  return cli_->Get(path, headers, std::move(response_handler),
      std::move(content_receiver), std::move(progress));
}
inline Result Client::Get(const char *path, const Params &params,
    const Headers &headers, Progress progress) {
  return cli_->Get(path, params, headers, progress);
}
inline Result Client::Get(const char *path, const Params &params,
    const Headers &headers,
    ContentReceiver content_receiver, Progress progress) {
  return cli_->Get(path, params, headers, content_receiver, progress);
}
inline Result Client::Get(const char *path, const Params &params,
    const Headers &headers,
    ResponseHandler response_handler,
    ContentReceiver content_receiver, Progress progress) {
  return cli_->Get(path, params, headers, response_handler, content_receiver,
      progress);
}

inline Result Client::Head(const char *path) { return cli_->Head(path); }
inline Result Client::Head(const char *path, const Headers &headers) {
  return cli_->Head(path, headers);
}

inline Result Client::Post(const char *path) { return cli_->Post(path); }
inline Result Client::Post(const char *path, const char *body,
    size_t content_length, const char *content_type) {
  return cli_->Post(path, body, content_length, content_type);
}
inline Result Client::Post(const char *path, const Headers &headers,
    const char *body, size_t content_length,
    const char *content_type) {
  return cli_->Post(path, headers, body, content_length, content_type);
}
inline Result Client::Post(const char *path, const std::string &body,
    const char *content_type) {
  return cli_->Post(path, body, content_type);
}
inline Result Client::Post(const char *path, const Headers &headers,
    const std::string &body, const char *content_type) {
  return cli_->Post(path, headers, body, content_type);
}
inline Result Client::Post(const char *path, size_t content_length,
    ContentProvider content_provider,
    const char *content_type) {
  return cli_->Post(path, content_length, std::move(content_provider),
      content_type);
}
inline Result Client::Post(const char *path,
    ContentProviderWithoutLength content_provider,
    const char *content_type) {
  return cli_->Post(path, std::move(content_provider), content_type);
}
inline Result Client::Post(const char *path, const Headers &headers,
    size_t content_length,
    ContentProvider content_provider,
    const char *content_type) {
  return cli_->Post(path, headers, content_length, std::move(content_provider),
      content_type);
}
inline Result Client::Post(const char *path, const Headers &headers,
    ContentProviderWithoutLength content_provider,
    const char *content_type) {
  return cli_->Post(path, headers, std::move(content_provider), content_type);
}
inline Result Client::Post(const char *path, const Params &params) {
  return cli_->Post(path, params);
}
inline Result Client::Post(const char *path, const Headers &headers,
    const Params &params) {
  return cli_->Post(path, headers, params);
}
inline Result Client::Post(const char *path,
    const MultipartFormDataItems &items) {
  return cli_->Post(path, items);
}
inline Result Client::Post(const char *path, const Headers &headers,
    const MultipartFormDataItems &items) {
  return cli_->Post(path, headers, items);
}
inline Result Client::Post(const char *path, const Headers &headers,
    const MultipartFormDataItems &items,
    const std::string &boundary) {
  return cli_->Post(path, headers, items, boundary);
}
inline Result Client::Put(const char *path) { return cli_->Put(path); }
inline Result Client::Put(const char *path, const char *body,
    size_t content_length, const char *content_type) {
  return cli_->Put(path, body, content_length, content_type);
}
inline Result Client::Put(const char *path, const Headers &headers,
    const char *body, size_t content_length,
    const char *content_type) {
  return cli_->Put(path, headers, body, content_length, content_type);
}
inline Result Client::Put(const char *path, const std::string &body,
    const char *content_type) {
  return cli_->Put(path, body, content_type);
}
inline Result Client::Put(const char *path, const Headers &headers,
    const std::string &body, const char *content_type) {
  return cli_->Put(path, headers, body, content_type);
}
inline Result Client::Put(const char *path, size_t content_length,
    ContentProvider content_provider,
    const char *content_type) {
  return cli_->Put(path, content_length, std::move(content_provider),
      content_type);
}
inline Result Client::Put(const char *path,
    ContentProviderWithoutLength content_provider,
    const char *content_type) {
  return cli_->Put(path, std::move(content_provider), content_type);
}
inline Result Client::Put(const char *path, const Headers &headers,
    size_t content_length,
    ContentProvider content_provider,
    const char *content_type) {
  return cli_->Put(path, headers, content_length, std::move(content_provider),
      content_type);
}
inline Result Client::Put(const char *path, const Headers &headers,
    ContentProviderWithoutLength content_provider,
    const char *content_type) {
  return cli_->Put(path, headers, std::move(content_provider), content_type);
}
inline Result Client::Put(const char *path, const Params &params) {
  return cli_->Put(path, params);
}
inline Result Client::Put(const char *path, const Headers &headers,
    const Params &params) {
  return cli_->Put(path, headers, params);
}
inline Result Client::Patch(const char *path) { return cli_->Patch(path); }
inline Result Client::Patch(const char *path, const char *body,
    size_t content_length, const char *content_type) {
  return cli_->Patch(path, body, content_length, content_type);
}
inline Result Client::Patch(const char *path, const Headers &headers,
    const char *body, size_t content_length,
    const char *content_type) {
  return cli_->Patch(path, headers, body, content_length, content_type);
}
inline Result Client::Patch(const char *path, const std::string &body,
    const char *content_type) {
  return cli_->Patch(path, body, content_type);
}
inline Result Client::Patch(const char *path, const Headers &headers,
    const std::string &body, const char *content_type) {
  return cli_->Patch(path, headers, body, content_type);
}
inline Result Client::Patch(const char *path, size_t content_length,
    ContentProvider content_provider,
    const char *content_type) {
  return cli_->Patch(path, content_length, std::move(content_provider),
      content_type);
}
inline Result Client::Patch(const char *path,
    ContentProviderWithoutLength content_provider,
    const char *content_type) {
  return cli_->Patch(path, std::move(content_provider), content_type);
}
inline Result Client::Patch(const char *path, const Headers &headers,
    size_t content_length,
    ContentProvider content_provider,
    const char *content_type) {
  return cli_->Patch(path, headers, content_length, std::move(content_provider),
      content_type);
}
inline Result Client::Patch(const char *path, const Headers &headers,
    ContentProviderWithoutLength content_provider,
    const char *content_type) {
  return cli_->Patch(path, headers, std::move(content_provider), content_type);
}
inline Result Client::Delete(const char *path) { return cli_->Delete(path); }
inline Result Client::Delete(const char *path, const Headers &headers) {
  return cli_->Delete(path, headers);
}
inline Result Client::Delete(const char *path, const char *body,
    size_t content_length, const char *content_type) {
  return cli_->Delete(path, body, content_length, content_type);
}
inline Result Client::Delete(const char *path, const Headers &headers,
    const char *body, size_t content_length,
    const char *content_type) {
  return cli_->Delete(path, headers, body, content_length, content_type);
}
inline Result Client::Delete(const char *path, const std::string &body,
    const char *content_type) {
  return cli_->Delete(path, body, content_type);
}
inline Result Client::Delete(const char *path, const Headers &headers,
    const std::string &body,
    const char *content_type) {
  return cli_->Delete(path, headers, body, content_type);
}
inline Result Client::Options(const char *path) { return cli_->Options(path); }
inline Result Client::Options(const char *path, const Headers &headers) {
  return cli_->Options(path, headers);
}

inline bool Client::send(Request &req, Response &res, Error &error) {
  return cli_->send(req, res, error);
}

inline Result Client::send(const Request &req) { return cli_->send(req); }

inline size_t Client::is_socket_open() const { return cli_->is_socket_open(); }

inline void Client::stop() { cli_->stop(); }

inline void Client::set_default_headers(Headers headers) {
  cli_->set_default_headers(std::move(headers));
}

inline void Client::set_tcp_nodelay(bool on) { cli_->set_tcp_nodelay(on); }
inline void Client::set_socket_options(SocketOptions socket_options) {
  cli_->set_socket_options(std::move(socket_options));
}

inline void Client::set_connection_timeout(time_t sec, time_t usec) {
  cli_->set_connection_timeout(sec, usec);
}
inline void Client::set_read_timeout(time_t sec, time_t usec) {
  cli_->set_read_timeout(sec, usec);
}
inline void Client::set_write_timeout(time_t sec, time_t usec) {
  cli_->set_write_timeout(sec, usec);
}

inline void Client::set_basic_auth(const char *username, const char *password) {
  cli_->set_basic_auth(username, password);
}
inline void Client::set_bearer_token_auth(const char *token) {
  cli_->set_bearer_token_auth(token);
}
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline void Client::set_digest_auth(const char *username,
    const char *password) {
  cli_->set_digest_auth(username, password);
}
#endif

inline void Client::set_keep_alive(bool on) { cli_->set_keep_alive(on); }
inline void Client::set_follow_location(bool on) {
  cli_->set_follow_location(on);
}

inline void Client::set_compress(bool on) { cli_->set_compress(on); }

inline void Client::set_decompress(bool on) { cli_->set_decompress(on); }

inline void Client::set_interface(const char *intf) {
  cli_->set_interface(intf);
}

inline void Client::set_proxy(const char *host, int port) {
  cli_->set_proxy(host, port);
}
inline void Client::set_proxy_basic_auth(const char *username,
    const char *password) {
  cli_->set_proxy_basic_auth(username, password);
}
inline void Client::set_proxy_bearer_token_auth(const char *token) {
  cli_->set_proxy_bearer_token_auth(token);
}
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline void Client::set_proxy_digest_auth(const char *username,
    const char *password) {
  cli_->set_proxy_digest_auth(username, password);
}
#endif

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline void Client::enable_server_certificate_verification(bool enabled) {
  cli_->enable_server_certificate_verification(enabled);
}
#endif

inline void Client::set_logger(Logger logger) { cli_->set_logger(logger); }

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
inline void Client::set_ca_cert_path(const char *ca_cert_file_path,
    const char *ca_cert_dir_path) {
  if (is_ssl_) {
    static_cast<SSLClient &>(*cli_).set_ca_cert_path(ca_cert_file_path,
        ca_cert_dir_path);
  }
}

inline void Client::set_ca_cert_store(X509_STORE *ca_cert_store) {
  if (is_ssl_) {
    static_cast<SSLClient &>(*cli_).set_ca_cert_store(ca_cert_store);
  }
}

inline long Client::get_openssl_verify_result() const {
  if (is_ssl_) {
    return static_cast<SSLClient &>(*cli_).get_openssl_verify_result();
  }
  return -1; // NOTE: -1 doesn't match any of X509_V_ERR_???
}

inline SSL_CTX *Client::ssl_context() const {
  if (is_ssl_) { return static_cast<SSLClient &>(*cli_).ssl_context(); }
  return nullptr;
}
#endif
