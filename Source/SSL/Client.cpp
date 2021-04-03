// Joan Andrés (@Andres6936) Github.

#include "Httplib/SSL/Client.hpp"

using namespace httplib;

#ifdef CPPHTTPLIB_OPENSSL_SUPPORT

// SSL HTTP client implementation
SSLClient::SSLClient(const std::string &host)
    : SSLClient(host, 443, std::string(), std::string()) {}

SSLClient::SSLClient(const std::string &host, int port)
    : SSLClient(host, port, std::string(), std::string()) {}

SSLClient::SSLClient(const std::string &host, int port,
    const std::string &client_cert_path,
    const std::string &client_key_path)
    : ClientImpl(host, port, client_cert_path, client_key_path) {
  ctx_ = SSL_CTX_new(SSLv23_client_method());

  detail::split(&host_[0], &host_[host_.size()], '.',
      [&](const char *b, const char *e) {
        host_components_.emplace_back(std::string(b, e));
      });
  if (!client_cert_path.empty() && !client_key_path.empty()) {
    if (SSL_CTX_use_certificate_file(ctx_, client_cert_path.c_str(),
        SSL_FILETYPE_PEM) != 1 ||
        SSL_CTX_use_PrivateKey_file(ctx_, client_key_path.c_str(),
            SSL_FILETYPE_PEM) != 1) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }
}

SSLClient::SSLClient(const std::string &host, int port,
    X509 *client_cert, EVP_PKEY *client_key)
    : ClientImpl(host, port) {
  ctx_ = SSL_CTX_new(SSLv23_client_method());

  detail::split(&host_[0], &host_[host_.size()], '.',
      [&](const char *b, const char *e) {
        host_components_.emplace_back(std::string(b, e));
      });
  if (client_cert != nullptr && client_key != nullptr) {
    if (SSL_CTX_use_certificate(ctx_, client_cert) != 1 ||
        SSL_CTX_use_PrivateKey(ctx_, client_key) != 1) {
      SSL_CTX_free(ctx_);
      ctx_ = nullptr;
    }
  }
}

SSLClient::~SSLClient() {
  if (ctx_) { SSL_CTX_free(ctx_); }
  // Make sure to shut down SSL since shutdown_ssl will resolve to the
  // base function rather than the derived function once we get to the
  // base class destructor, and won't free the SSL (causing a leak).
  SSLClient::shutdown_ssl(socket_, true);
}

bool SSLClient::is_valid() const { return ctx_; }

void SSLClient::set_ca_cert_path(const char *ca_cert_file_path,
    const char *ca_cert_dir_path) {
  if (ca_cert_file_path) { ca_cert_file_path_ = ca_cert_file_path; }
  if (ca_cert_dir_path) { ca_cert_dir_path_ = ca_cert_dir_path; }
}

void SSLClient::set_ca_cert_store(X509_STORE *ca_cert_store) {
  if (ca_cert_store) {
    if (ctx_) {
      if (SSL_CTX_get_cert_store(ctx_) != ca_cert_store) {
        // Free memory allocated for old cert and use new store `ca_cert_store`
        SSL_CTX_set_cert_store(ctx_, ca_cert_store);
      }
    } else {
      X509_STORE_free(ca_cert_store);
    }
  }
}

long SSLClient::get_openssl_verify_result() const {
  return verify_result_;
}

SSL_CTX *SSLClient::ssl_context() const { return ctx_; }

bool SSLClient::create_and_connect_socket(Socket &socket, Error &error) {
  return is_valid() && ClientImpl::create_and_connect_socket(socket, error);
}

// Assumes that socket_mutex_ is locked and that there are no requests in flight
bool SSLClient::connect_with_proxy(Socket &socket, Response &res,
    bool &success, Error &error) {
  success = true;
  Response res2;
  if (!detail::process_client_socket(
      socket.sock, read_timeout_sec_, read_timeout_usec_,
      write_timeout_sec_, write_timeout_usec_, [&](Stream &strm) {
        Request req2;
        req2.method = "CONNECT";
        req2.path = host_and_port_;
        return process_request(strm, req2, res2, false, error);
      })) {
    // Thread-safe to close everything because we are assuming there are no
    // requests in flight
    shutdown_ssl(socket, true);
    shutdown_socket(socket);
    close_socket(socket);
    success = false;
    return false;
  }

  if (res2.status == 407) {
    if (!proxy_digest_auth_username_.empty() &&
        !proxy_digest_auth_password_.empty()) {
      std::map<std::string, std::string> auth;
      if (detail::parse_www_authenticate(res2, auth, true)) {
        Response res3;
        if (!detail::process_client_socket(
            socket.sock, read_timeout_sec_, read_timeout_usec_,
            write_timeout_sec_, write_timeout_usec_, [&](Stream &strm) {
              Request req3;
              req3.method = "CONNECT";
              req3.path = host_and_port_;
              req3.headers.insert(detail::make_digest_authentication_header(
                  req3, auth, 1, detail::random_string(10),
                  proxy_digest_auth_username_, proxy_digest_auth_password_,
                  true));
              return process_request(strm, req3, res3, false, error);
            })) {
          // Thread-safe to close everything because we are assuming there are
          // no requests in flight
          shutdown_ssl(socket, true);
          shutdown_socket(socket);
          close_socket(socket);
          success = false;
          return false;
        }
      }
    } else {
      res = res2;
      return false;
    }
  }

  return true;
}

bool SSLClient::load_certs() {
  bool ret = true;

  std::call_once(initialize_cert_, [&]() {
    std::lock_guard<std::mutex> guard(ctx_mutex_);
    if (!ca_cert_file_path_.empty()) {
      if (!SSL_CTX_load_verify_locations(ctx_, ca_cert_file_path_.c_str(),
          nullptr)) {
        ret = false;
      }
    } else if (!ca_cert_dir_path_.empty()) {
      if (!SSL_CTX_load_verify_locations(ctx_, nullptr,
          ca_cert_dir_path_.c_str())) {
        ret = false;
      }
    } else {
#ifdef _WIN32
      detail::load_system_certs_on_windows(SSL_CTX_get_cert_store(ctx_));
#else
      SSL_CTX_set_default_verify_paths(ctx_);
#endif
    }
  });

  return ret;
}

bool SSLClient::initialize_ssl(Socket &socket, Error &error) {
  auto ssl = detail::ssl_new(
      socket.sock, ctx_, ctx_mutex_,
      [&](SSL *ssl) {
        if (server_certificate_verification_) {
          if (!load_certs()) {
            error = Error::SSLLoadingCerts;
            return false;
          }
          SSL_set_verify(ssl, SSL_VERIFY_NONE, nullptr);
        }

        if (!detail::ssl_connect_or_accept_nonblocking(
            socket.sock, ssl, SSL_connect, connection_timeout_sec_,
            connection_timeout_usec_)) {
          error = Error::SSLConnection;
          return false;
        }

        if (server_certificate_verification_) {
          verify_result_ = SSL_get_verify_result(ssl);

          if (verify_result_ != X509_V_OK) {
            error = Error::SSLServerVerification;
            return false;
          }

          auto server_cert = SSL_get_peer_certificate(ssl);

          if (server_cert == nullptr) {
            error = Error::SSLServerVerification;
            return false;
          }

          if (!verify_host(server_cert)) {
            X509_free(server_cert);
            error = Error::SSLServerVerification;
            return false;
          }
          X509_free(server_cert);
        }

        return true;
      },
      [&](SSL *ssl) {
        SSL_set_tlsext_host_name(ssl, host_.c_str());
        return true;
      });

  if (ssl) {
    socket.ssl = ssl;
    return true;
  }

  shutdown_socket(socket);
  close_socket(socket);
  return false;
}

void SSLClient::shutdown_ssl(Socket &socket, bool shutdown_gracefully) {
  if (socket.sock == INVALID_SOCKET) {
    assert(socket.ssl == nullptr);
    return;
  }
  if (socket.ssl) {
    detail::ssl_delete(ctx_mutex_, socket.ssl, shutdown_gracefully);
    socket.ssl = nullptr;
  }
  assert(socket.ssl == nullptr);
}

bool
SSLClient::process_socket(const Socket &socket,
    std::function<bool(Stream &strm)> callback) {
  assert(socket.ssl);
  return detail::process_client_socket_ssl(
      socket.ssl, socket.sock, read_timeout_sec_, read_timeout_usec_,
      write_timeout_sec_, write_timeout_usec_, std::move(callback));
}

bool SSLClient::is_ssl() const { return true; }

bool SSLClient::verify_host(X509 *server_cert) const {
  /* Quote from RFC2818 section 3.1 "Server Identity"

     If a subjectAltName extension of type dNSName is present, that MUST
     be used as the identity. Otherwise, the (most specific) Common Name
     field in the Subject field of the certificate MUST be used. Although
     the use of the Common Name is existing practice, it is deprecated and
     Certification Authorities are encouraged to use the dNSName instead.

     Matching is performed using the matching rules specified by
     [RFC2459].  If more than one identity of a given type is present in
     the certificate (e.g., more than one dNSName name, a match in any one
     of the set is considered acceptable.) Names may contain the wildcard
     character * which is considered to match any single domain name
     component or component fragment. E.g., *.a.com matches foo.a.com but
     not bar.foo.a.com. f*.com matches foo.com but not bar.com.

     In some cases, the URI is specified as an IP address rather than a
     hostname. In this case, the iPAddress subjectAltName must be present
     in the certificate and must exactly match the IP in the URI.

  */
  return verify_host_with_subject_alt_name(server_cert) ||
         verify_host_with_common_name(server_cert);
}

bool
SSLClient::verify_host_with_subject_alt_name(X509 *server_cert) const {
  auto ret = false;

  auto type = GEN_DNS;

  struct in6_addr addr6;
  struct in_addr addr;
  size_t addr_len = 0;

#ifndef __MINGW32__
  if (inet_pton(AF_INET6, host_.c_str(), &addr6)) {
    type = GEN_IPADD;
    addr_len = sizeof(struct in6_addr);
  } else if (inet_pton(AF_INET, host_.c_str(), &addr)) {
    type = GEN_IPADD;
    addr_len = sizeof(struct in_addr);
  }
#endif

  auto alt_names = static_cast<const struct stack_st_GENERAL_NAME *>(
      X509_get_ext_d2i(server_cert, NID_subject_alt_name, nullptr, nullptr));

  if (alt_names) {
    auto dsn_matched = false;
    auto ip_mached = false;

    auto count = sk_GENERAL_NAME_num(alt_names);

    for (decltype(count) i = 0; i < count && !dsn_matched; i++) {
      auto val = sk_GENERAL_NAME_value(alt_names, i);
      if (val->type == type) {
        auto name = (const char *)ASN1_STRING_get0_data(val->d.ia5);
        auto name_len = (size_t)ASN1_STRING_length(val->d.ia5);

        switch (type) {
        case GEN_DNS: dsn_matched = check_host_name(name, name_len); break;

        case GEN_IPADD:
          if (!memcmp(&addr6, name, addr_len) ||
              !memcmp(&addr, name, addr_len)) {
            ip_mached = true;
          }
          break;
        }
      }
    }

    if (dsn_matched || ip_mached) { ret = true; }
  }

  GENERAL_NAMES_free((STACK_OF(GENERAL_NAME) *)alt_names);
  return ret;
}

bool SSLClient::verify_host_with_common_name(X509 *server_cert) const {
  const auto subject_name = X509_get_subject_name(server_cert);

  if (subject_name != nullptr) {
    char name[BUFSIZ];
    auto name_len = X509_NAME_get_text_by_NID(subject_name, NID_commonName,
        name, sizeof(name));

    if (name_len != -1) {
      return check_host_name(name, static_cast<size_t>(name_len));
    }
  }

  return false;
}

bool SSLClient::check_host_name(const char *pattern,
    size_t pattern_len) const {
  if (host_.size() == pattern_len && host_ == pattern) { return true; }

  // Wildcard match
  // https://bugs.launchpad.net/ubuntu/+source/firefox-3.0/+bug/376484
  std::vector<std::string> pattern_components;
  detail::split(&pattern[0], &pattern[pattern_len], '.',
      [&](const char *b, const char *e) {
        pattern_components.emplace_back(std::string(b, e));
      });

  if (host_components_.size() != pattern_components.size()) { return false; }

  auto itr = pattern_components.begin();
  for (const auto &h : host_components_) {
    auto &p = *itr;
    if (p != h && p != "*") {
      auto partial_match = (p.size() > 0 && p[p.size() - 1] == '*' &&
                            !p.compare(0, p.size() - 1, h));
      if (!partial_match) { return false; }
    }
    ++itr;
  }

  return true;
}

#endif