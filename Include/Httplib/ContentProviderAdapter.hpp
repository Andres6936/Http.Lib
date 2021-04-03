// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_CONTENTPROVIDERADAPTER_HPP
#define HTTPLIB_CONTENTPROVIDERADAPTER_HPP

namespace httplib {

namespace detail {

class ContentProviderAdapter {
public:
  explicit ContentProviderAdapter(
      ContentProviderWithoutLength &&content_provider)
      : content_provider_(content_provider) {}

  bool operator()(size_t offset, size_t, DataSink &sink) {
    return content_provider_(offset, sink);
  }

private:
  ContentProviderWithoutLength content_provider_;
};


}

} // namespace httplib

#endif // HTTPLIB_CONTENTPROVIDERADAPTER_HPP
