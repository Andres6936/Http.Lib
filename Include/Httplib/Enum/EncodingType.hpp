// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_ENCODINGTYPE_HPP
#define HTTPLIB_ENCODINGTYPE_HPP

namespace httplib {

namespace detail {

enum class EncodingType { None = 0, Gzip, Brotli };

inline EncodingType encoding_type(const Request &req, const Response &res) {
  auto ret =
      detail::can_compress_content_type(res.get_header_value("Content-Type"));
  if (!ret) { return EncodingType::None; }

  const auto &s = req.get_header_value("Accept-Encoding");
  (void)(s);

#ifdef CPPHTTPLIB_BROTLI_SUPPORT
  // TODO: 'Accept-Encoding' has br, not br;q=0
  ret = s.find("br") != std::string::npos;
  if (ret) { return EncodingType::Brotli; }
#endif

#ifdef CPPHTTPLIB_ZLIB_SUPPORT
  // TODO: 'Accept-Encoding' has gzip, not gzip;q=0
  ret = s.find("gzip") != std::string::npos;
  if (ret) { return EncodingType::Gzip; }
#endif

  return EncodingType::None;
}

}

} // namespace httplib

#endif // HTTPLIB_ENCODINGTYPE_HPP
