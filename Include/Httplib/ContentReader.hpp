// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_CONTENTREADER_HPP
#define HTTPLIB_CONTENTREADER_HPP

#include <Httplib/Using/ContentReceiver.hpp>

namespace httplib {

class ContentReader {
public:
  using Reader = std::function<bool(ContentReceiver receiver)>;
  using MultipartReader = std::function<bool(MultipartContentHeader header,
  ContentReceiver receiver)>;

  ContentReader(Reader reader, MultipartReader multipart_reader)
      : reader_(std::move(reader)),
        multipart_reader_(std::move(multipart_reader)) {}

  bool operator()(MultipartContentHeader header,
      ContentReceiver receiver) const {
    return multipart_reader_(std::move(header), std::move(receiver));
  }

  bool operator()(ContentReceiver receiver) const {
    return reader_(std::move(receiver));
  }

  Reader reader_;
  MultipartReader multipart_reader_;
};

} // namespace httplib

#endif // HTTPLIB_CONTENTREADER_HPP
