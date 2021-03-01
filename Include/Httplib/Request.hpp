// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_REQUEST_HPP
#define HTTPLIB_REQUEST_HPP

#include <string>

#include <Httplib/Headers.hpp>
#include <Httplib/DataSink.hpp>
#include <Httplib/MultipartFormData.hpp>
#include <Httplib/Using/Match.hpp>
#include <Httplib/Using/Params.hpp>
#include <Httplib/Using/Ranges.hpp>
#include <Httplib/Using/Progress.hpp>

namespace httplib {


struct Request {
  std::string method;
  std::string path;
  Headers headers;
  std::string body;

  std::string remote_addr;
  int remote_port = -1;

  // for server
  std::string version;
  std::string target;
  Params params;
  MultipartFormDataMap files;
  Ranges ranges;
  Match matches;

  // for client
  ResponseHandler response_handler;
  ContentReceiverWithProgress content_receiver;
  Progress progress;
#ifdef CPPHTTPLIB_OPENSSL_SUPPORT
  const SSL *ssl;
#endif

  bool has_header(const char *key) const;
  std::string get_header_value(const char *key, size_t id = 0) const;
  template <typename T>
  T get_header_value(const char *key, size_t id = 0) const;
  size_t get_header_value_count(const char *key) const;
  void set_header(const char *key, const char *val);
  void set_header(const char *key, const std::string &val);

  bool has_param(const char *key) const;
  std::string get_param_value(const char *key, size_t id = 0) const;
  size_t get_param_value_count(const char *key) const;

  bool is_multipart_form_data() const;

  bool has_file(const char *key) const;
  MultipartFormData get_file_value(const char *key) const;

  // private members...
  size_t redirect_count_ = CPPHTTPLIB_REDIRECT_MAX_COUNT;
  size_t content_length_ = 0;
  ContentProvider content_provider_;
  bool is_chunked_content_provider_ = false;
  size_t authorization_count_ = 0;
};

} // namespace httplib

#endif // HTTPLIB_REQUEST_HPP
