// Joan Andrés (@Andres6936) Github.

#include "httplib/BufferStream.hpp"

using namespace httplib;


// Buffer stream implementation
inline bool BufferStream::is_readable() const { return true; }

inline bool BufferStream::is_writable() const { return true; }

inline ssize_t BufferStream::read(char *ptr, size_t size) {
#if defined(_MSC_VER) && _MSC_VER <= 1900
  auto len_read = buffer._Copy_s(ptr, size, size, position);
#else
  auto len_read = buffer.copy(ptr, size, position);
#endif
  position += static_cast<size_t>(len_read);
  return static_cast<ssize_t>(len_read);
}

inline ssize_t BufferStream::write(const char *ptr, size_t size) {
  buffer.append(ptr, size);
  return static_cast<ssize_t>(size);
}

inline void BufferStream::get_remote_ip_and_port(std::string & /*ip*/,
    int & /*port*/) const {}

inline socket_t BufferStream::socket() const { return 0; }

inline const std::string &BufferStream::get_buffer() const { return buffer; }