// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_NOCOMPRESSOR_HPP
#define HTTPLIB_NOCOMPRESSOR_HPP

namespace httplib {

namespace detail {

class nocompressor : public compressor {
public:
  ~nocompressor(){};

  bool compress(const char *data, size_t data_length, bool /*last*/,
      Callback callback) override {
    if (!data_length) { return true; }
    return callback(data, data_length);
  }
};

}

} // namespace httplib

#endif // HTTPLIB_NOCOMPRESSOR_HPP
