// Joan Andrés (@Andres6936) Github.

#include <array>
#include <vector>
#include <cstring>

#include "Httplib/Stream.hpp"

using namespace httplib;


// Stream implementation
ssize_t Stream::write(const char *ptr) {
  return write(ptr, std::strlen(ptr));
}

ssize_t Stream::write(const std::string &s) {
  return write(s.data(), s.size());
}
