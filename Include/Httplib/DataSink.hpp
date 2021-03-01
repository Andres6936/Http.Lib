// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_DATASINK_HPP
#define HTTPLIB_DATASINK_HPP

namespace httplib {

class DataSink {
public:
  DataSink() : os(&sb_), sb_(*this) {}

  DataSink(const DataSink &) = delete;
  DataSink &operator=(const DataSink &) = delete;
  DataSink(DataSink &&) = delete;
  DataSink &operator=(DataSink &&) = delete;

  std::function<void(const char *data, size_t data_len)> write;
  std::function<void()> done;
  std::function<bool()> is_writable;
  std::ostream os;

private:
  class data_sink_streambuf : public std::streambuf {
  public:
    explicit data_sink_streambuf(DataSink &sink) : sink_(sink) {}

  protected:
    std::streamsize xsputn(const char *s, std::streamsize n) {
      sink_.write(s, static_cast<size_t>(n));
      return n;
    }

  private:
    DataSink &sink_;
  };

  data_sink_streambuf sb_;
};

using ContentProvider =
std::function<bool(size_t offset, size_t length, DataSink &sink)>;

using ContentProviderWithoutLength =
std::function<bool(size_t offset, DataSink &sink)>;

using ContentReceiverWithProgress =
std::function<bool(const char *data, size_t data_length, uint64_t offset,
    uint64_t total_length)>;

} // namespace httplib

#endif // HTTPLIB_DATASINK_HPP
