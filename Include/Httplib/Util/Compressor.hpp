// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_COMPRESSOR_HPP
#define HTTPLIB_COMPRESSOR_HPP

namespace httplib {

namespace detail {

class compressor {
public:
  virtual ~compressor(){};

  typedef std::function<bool(const char *data, size_t data_len)> Callback;
  virtual bool compress(const char *data, size_t data_length, bool last,
      Callback callback) = 0;
};

}

} // namespace httplib

#endif // HTTPLIB_COMPRESSOR_HPP
