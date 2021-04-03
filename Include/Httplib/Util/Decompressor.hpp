// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_DECOMPRESSOR_HPP
#define HTTPLIB_DECOMPRESSOR_HPP

namespace httplib {

namespace detail {

class decompressor {
public:
  virtual ~decompressor() {}

  virtual bool is_valid() const = 0;

  typedef std::function<bool(const char *data, size_t data_len)> Callback;
  virtual bool decompress(const char *data, size_t data_length,
      Callback callback) = 0;
};

}

} // namespace httplib

#endif // HTTPLIB_DECOMPRESSOR_HPP
