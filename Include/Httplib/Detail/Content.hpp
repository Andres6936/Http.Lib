// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_CONTENT_HPP
#define HTTPLIB_CONTENT_HPP

#include <Httplib/Enum/Error.hpp>
#include <Httplib/Detail/Header.hpp>
#include <Httplib/Util/Decompressor.hpp>

namespace httplib {

namespace detail {

inline bool read_content_with_length(Stream &strm, uint64_t len,
    Progress progress,
    ContentReceiverWithProgress out) {
  char buf[CPPHTTPLIB_RECV_BUFSIZ];

  uint64_t r = 0;
  while (r < len) {
    auto read_len = static_cast<size_t>(len - r);
    auto n = strm.read(buf, (std::min)(read_len, CPPHTTPLIB_RECV_BUFSIZ));
    if (n <= 0) { return false; }

    if (!out(buf, static_cast<size_t>(n), r, len)) { return false; }
    r += static_cast<uint64_t>(n);

    if (progress) {
      if (!progress(r, len)) { return false; }
    }
  }

  return true;
}

inline void skip_content_with_length(Stream &strm, uint64_t len) {
  char buf[CPPHTTPLIB_RECV_BUFSIZ];
  uint64_t r = 0;
  while (r < len) {
    auto read_len = static_cast<size_t>(len - r);
    auto n = strm.read(buf, (std::min)(read_len, CPPHTTPLIB_RECV_BUFSIZ));
    if (n <= 0) { return; }
    r += static_cast<uint64_t>(n);
  }
}

inline bool read_content_without_length(Stream &strm,
    ContentReceiverWithProgress out) {
  char buf[CPPHTTPLIB_RECV_BUFSIZ];
  uint64_t r = 0;
  for (;;) {
    auto n = strm.read(buf, CPPHTTPLIB_RECV_BUFSIZ);
    if (n < 0) {
      return false;
    } else if (n == 0) {
      return true;
    }

    if (!out(buf, static_cast<size_t>(n), r, 0)) { return false; }
    r += static_cast<uint64_t>(n);
  }

  return true;
}

inline bool read_content_chunked(Stream &strm,
    ContentReceiverWithProgress out) {
  const auto bufsiz = 16;
  char buf[bufsiz];

  stream_line_reader line_reader(strm, buf, bufsiz);

  if (!line_reader.getline()) { return false; }

  unsigned long chunk_len;
  while (true) {
    char *end_ptr;

    chunk_len = std::strtoul(line_reader.ptr(), &end_ptr, 16);

    if (end_ptr == line_reader.ptr()) { return false; }
    if (chunk_len == ULONG_MAX) { return false; }

    if (chunk_len == 0) { break; }

    if (!read_content_with_length(strm, chunk_len, nullptr, out)) {
      return false;
    }

    if (!line_reader.getline()) { return false; }

    if (strcmp(line_reader.ptr(), "\r\n")) { break; }

    if (!line_reader.getline()) { return false; }
  }

  if (chunk_len == 0) {
    // Reader terminator after chunks
    if (!line_reader.getline() || strcmp(line_reader.ptr(), "\r\n"))
      return false;
  }

  return true;
}


template <typename T, typename U>
bool prepare_content_receiver(T &x, int &status,
    ContentReceiverWithProgress receiver,
    bool decompress, U callback) {
  if (decompress) {
    std::string encoding = x.get_header_value("Content-Encoding");
    std::unique_ptr<decompressor> decompressor;

    if (encoding.find("gzip") != std::string::npos ||
        encoding.find("deflate") != std::string::npos) {
#ifdef CPPHTTPLIB_ZLIB_SUPPORT
      decompressor = detail::make_unique<gzip_decompressor>();
#else
      status = 415;
      return false;
#endif
    } else if (encoding.find("br") != std::string::npos) {
#ifdef CPPHTTPLIB_BROTLI_SUPPORT
      decompressor = detail::make_unique<brotli_decompressor>();
#else
      status = 415;
      return false;
#endif
    }

    if (decompressor) {
      if (decompressor->is_valid()) {
        ContentReceiverWithProgress out = [&](const char *buf, size_t n,
            uint64_t off, uint64_t len) {
          return decompressor->decompress(buf, n,
              [&](const char *buf, size_t n) {
                return receiver(buf, n, off, len);
              });
        };
        return callback(std::move(out));
      } else {
        status = 500;
        return false;
      }
    }
  }

  ContentReceiverWithProgress out = [&](const char *buf, size_t n, uint64_t off,
      uint64_t len) {
    return receiver(buf, n, off, len);
  };
  return callback(std::move(out));
}

inline bool is_chunked_transfer_encoding(const Headers &headers) {
  return !strcasecmp(get_header_value(headers, "Transfer-Encoding", 0, ""),
      "chunked");
}


template <typename T>
bool read_content(Stream &strm, T &x, size_t payload_max_length, int &status,
    Progress progress, ContentReceiverWithProgress receiver,
    bool decompress) {
  return prepare_content_receiver(
      x, status, std::move(receiver), decompress,
      [&](const ContentReceiverWithProgress &out) {
        auto ret = true;
        auto exceed_payload_max_length = false;

        if (is_chunked_transfer_encoding(x.headers)) {
          ret = read_content_chunked(strm, out);
        } else if (!has_header(x.headers, "Content-Length")) {
          ret = read_content_without_length(strm, out);
        } else {
          auto len = get_header_value<uint64_t>(x.headers, "Content-Length");
          if (len > payload_max_length) {
            exceed_payload_max_length = true;
            skip_content_with_length(strm, len);
            ret = false;
          } else if (len > 0) {
            ret = read_content_with_length(strm, len, std::move(progress), out);
          }
        }

        if (!ret) { status = exceed_payload_max_length ? 413 : 400; }
        return ret;
      });
}


template <typename T>
inline bool write_content(Stream &strm, const ContentProvider &content_provider,
    size_t offset, size_t length, T is_shutting_down,
    Error &error) {
  size_t end_offset = offset + length;
  auto ok = true;
  DataSink data_sink;

  data_sink.write = [&](const char *d, size_t l) {
    if (ok) {
      if (write_data(strm, d, l)) {
        offset += l;
      } else {
        ok = false;
      }
    }
  };

  data_sink.is_writable = [&](void) { return ok && strm.is_writable(); };

  while (offset < end_offset && !is_shutting_down()) {
    if (!content_provider(offset, end_offset - offset, data_sink)) {
      error = Error::Canceled;
      return false;
    }
    if (!ok) {
      error = Error::Write;
      return false;
    }
  }

  error = Error::Success;
  return true;
}

template <typename T>
inline bool write_content(Stream &strm, const ContentProvider &content_provider,
    size_t offset, size_t length,
    const T &is_shutting_down) {
  auto error = Error::Success;
  return write_content(strm, content_provider, offset, length, is_shutting_down,
      error);
}



template <typename T>
inline bool
write_content_without_length(Stream &strm,
    const ContentProvider &content_provider,
    const T &is_shutting_down) {
  size_t offset = 0;
  auto data_available = true;
  auto ok = true;
  DataSink data_sink;

  data_sink.write = [&](const char *d, size_t l) {
    if (ok) {
      offset += l;
      if (!write_data(strm, d, l)) { ok = false; }
    }
  };

  data_sink.done = [&](void) { data_available = false; };

  data_sink.is_writable = [&](void) { return ok && strm.is_writable(); };

  while (data_available && !is_shutting_down()) {
    if (!content_provider(offset, 0, data_sink)) { return false; }
    if (!ok) { return false; }
  }
  return true;
}

template <typename T, typename U>
inline bool
write_content_chunked(Stream &strm, const ContentProvider &content_provider,
    const T &is_shutting_down, U &compressor, Error &error) {
  size_t offset = 0;
  auto data_available = true;
  auto ok = true;
  DataSink data_sink;

  data_sink.write = [&](const char *d, size_t l) {
    if (!ok) { return; }

    data_available = l > 0;
    offset += l;

    std::string payload;
    if (!compressor.compress(d, l, false,
        [&](const char *data, size_t data_len) {
          payload.append(data, data_len);
          return true;
        })) {
      ok = false;
      return;
    }

    if (!payload.empty()) {
      // Emit chunked response header and footer for each chunk
      auto chunk = from_i_to_hex(payload.size()) + "\r\n" + payload + "\r\n";
      if (!write_data(strm, chunk.data(), chunk.size())) {
        ok = false;
        return;
      }
    }
  };

  data_sink.done = [&](void) {
    if (!ok) { return; }

    data_available = false;

    std::string payload;
    if (!compressor.compress(nullptr, 0, true,
        [&](const char *data, size_t data_len) {
          payload.append(data, data_len);
          return true;
        })) {
      ok = false;
      return;
    }

    if (!payload.empty()) {
      // Emit chunked response header and footer for each chunk
      auto chunk = from_i_to_hex(payload.size()) + "\r\n" + payload + "\r\n";
      if (!write_data(strm, chunk.data(), chunk.size())) {
        ok = false;
        return;
      }
    }

    static const std::string done_marker("0\r\n\r\n");
    if (!write_data(strm, done_marker.data(), done_marker.size())) {
      ok = false;
    }
  };

  data_sink.is_writable = [&](void) { return ok && strm.is_writable(); };

  while (data_available && !is_shutting_down()) {
    if (!content_provider(offset, 0, data_sink)) {
      error = Error::Canceled;
      return false;
    }
    if (!ok) {
      error = Error::Write;
      return false;
    }
  }

  error = Error::Success;
  return true;
}

template <typename T, typename U>
inline bool write_content_chunked(Stream &strm,
    const ContentProvider &content_provider,
    const T &is_shutting_down, U &compressor) {
  auto error = Error::Success;
  return write_content_chunked(strm, content_provider, is_shutting_down,
      compressor, error);
}

inline std::string make_content_range_header_field(size_t offset, size_t length,
    size_t content_length) {
  std::string field = "bytes ";
  field += std::to_string(offset);
  field += "-";
  field += std::to_string(offset + length - 1);
  field += "/";
  field += std::to_string(content_length);
  return field;
}

}

} // namespace httplib

#endif // HTTPLIB_CONTENT_HPP
