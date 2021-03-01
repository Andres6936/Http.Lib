// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_RESULT_HPP
#define HTTPLIB_RESULT_HPP

#include <string>
#include <memory>

#include <Httplib/Headers.hpp>
#include <Httplib/Response.hpp>
#include <Httplib/Enum/Error.hpp>

namespace httplib {


class Result {
public:
  Result(std::unique_ptr<Response> &&res, Error err,
      Headers &&request_headers = Headers{})
      : res_(std::move(res)), err_(err),
        request_headers_(std::move(request_headers)) {}
  // Response
  operator bool() const { return res_ != nullptr; }
  bool operator==(std::nullptr_t) const { return res_ == nullptr; }
  bool operator!=(std::nullptr_t) const { return res_ != nullptr; }
  const Response &value() const { return *res_; }
  Response &value() { return *res_; }
  const Response &operator*() const { return *res_; }
  Response &operator*() { return *res_; }
  const Response *operator->() const { return res_.get(); }
  Response *operator->() { return res_.get(); }

  // Error
  Error error() const { return err_; }

  // Request Headers
  bool has_request_header(const char *key) const;
  std::string get_request_header_value(const char *key, size_t id = 0) const;
  template <typename T>
  T get_request_header_value(const char *key, size_t id = 0) const;
  size_t get_request_header_value_count(const char *key) const;

private:
  std::unique_ptr<Response> res_;
  Error err_;
  Headers request_headers_;
};


} // namespace httplib

#endif // HTTPLIB_RESULT_HPP
