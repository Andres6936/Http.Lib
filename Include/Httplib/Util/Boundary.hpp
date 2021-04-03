// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_BOUNDARY_HPP
#define HTTPLIB_BOUNDARY_HPP

#include <random>

namespace httplib {

namespace detail {

inline std::string make_multipart_data_boundary() {
  static const char data[] =
      "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

  // std::random_device might actually be deterministic on some
  // platforms, but due to lack of support in the c++ standard library,
  // doing better requires either some ugly hacks or breaking portability.
  std::random_device seed_gen;
  // Request 128 bits of entropy for initialization
  std::seed_seq seed_sequence{seed_gen(), seed_gen(), seed_gen(), seed_gen()};
  std::mt19937 engine(seed_sequence);

  std::string result = "--cpp-httplib-multipart-data-";

  for (auto i = 0; i < 16; i++) {
    result += data[engine() % (sizeof(data) - 1)];
  }

  return result;
}

inline bool parse_multipart_boundary(const std::string &content_type,
    std::string &boundary) {
  auto pos = content_type.find("boundary=");
  if (pos == std::string::npos) { return false; }
  boundary = content_type.substr(pos + 9);
  if (boundary.length() >= 2 && boundary.front() == '"' &&
      boundary.back() == '"') {
    boundary = boundary.substr(1, boundary.size() - 2);
  }
  return !boundary.empty();
}

}

} // namespace httplib

#endif // HTTPLIB_BOUNDARY_HPP
