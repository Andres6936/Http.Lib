// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_ZLIBCOMPRESSOR_HPP
#define HTTPLIB_ZLIBCOMPRESSOR_HPP

namespace httplib {


#ifdef CPPHTTPLIB_ZLIB_SUPPORT
class gzip_compressor : public compressor {
public:
  gzip_compressor() {
    std::memset(&strm_, 0, sizeof(strm_));
    strm_.zalloc = Z_NULL;
    strm_.zfree = Z_NULL;
    strm_.opaque = Z_NULL;

    is_valid_ = deflateInit2(&strm_, Z_DEFAULT_COMPRESSION, Z_DEFLATED, 31, 8,
        Z_DEFAULT_STRATEGY) == Z_OK;
  }

  ~gzip_compressor() { deflateEnd(&strm_); }

  bool compress(const char *data, size_t data_length, bool last,
      Callback callback) override {
    assert(is_valid_);

    auto flush = last ? Z_FINISH : Z_NO_FLUSH;

    strm_.avail_in = static_cast<decltype(strm_.avail_in)>(data_length);
    strm_.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(data));

    int ret = Z_OK;

    std::array<char, CPPHTTPLIB_COMPRESSION_BUFSIZ> buff{};
    do {
      strm_.avail_out = buff.size();
      strm_.next_out = reinterpret_cast<Bytef *>(buff.data());

      ret = deflate(&strm_, flush);
      if (ret == Z_STREAM_ERROR) { return false; }

      if (!callback(buff.data(), buff.size() - strm_.avail_out)) {
        return false;
      }
    } while (strm_.avail_out == 0);

    assert((last && ret == Z_STREAM_END) || (!last && ret == Z_OK));
    assert(strm_.avail_in == 0);
    return true;
  }

private:
  bool is_valid_ = false;
  z_stream strm_;
};

class gzip_decompressor : public decompressor {
public:
  gzip_decompressor() {
    std::memset(&strm_, 0, sizeof(strm_));
    strm_.zalloc = Z_NULL;
    strm_.zfree = Z_NULL;
    strm_.opaque = Z_NULL;

    // 15 is the value of wbits, which should be at the maximum possible value
    // to ensure that any gzip stream can be decoded. The offset of 32 specifies
    // that the stream type should be automatically detected either gzip or
    // deflate.
    is_valid_ = inflateInit2(&strm_, 32 + 15) == Z_OK;
  }

  ~gzip_decompressor() { inflateEnd(&strm_); }

  bool is_valid() const override { return is_valid_; }

  bool decompress(const char *data, size_t data_length,
      Callback callback) override {
    assert(is_valid_);

    int ret = Z_OK;

    strm_.avail_in = static_cast<decltype(strm_.avail_in)>(data_length);
    strm_.next_in = const_cast<Bytef *>(reinterpret_cast<const Bytef *>(data));

    std::array<char, CPPHTTPLIB_COMPRESSION_BUFSIZ> buff{};
    while (strm_.avail_in > 0) {
      strm_.avail_out = buff.size();
      strm_.next_out = reinterpret_cast<Bytef *>(buff.data());

      ret = inflate(&strm_, Z_NO_FLUSH);
      assert(ret != Z_STREAM_ERROR);
      switch (ret) {
      case Z_NEED_DICT:
      case Z_DATA_ERROR:
      case Z_MEM_ERROR: inflateEnd(&strm_); return false;
      }

      if (!callback(buff.data(), buff.size() - strm_.avail_out)) {
        return false;
      }
    }

    return ret == Z_OK || ret == Z_STREAM_END;
  }

private:
  bool is_valid_ = false;
  z_stream strm_;
};
#endif


} // namespace httplib

#endif // HTTPLIB_ZLIBCOMPRESSOR_HPP
