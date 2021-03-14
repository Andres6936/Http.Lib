// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_MIME_HPP
#define HTTPLIB_MIME_HPP

namespace httplib {

namespace detail {


inline const char *
find_content_type(const std::string &path,
    const std::map<std::string, std::string> &user_data) {
  auto ext = file_extension(path);

  auto it = user_data.find(ext);
  if (it != user_data.end()) { return it->second.c_str(); }

  using udl::operator""_;

  switch (str2tag(ext)) {
  default: return nullptr;
  case "css"_: return "text/css";
  case "csv"_: return "text/csv";
  case "txt"_: return "text/plain";
  case "vtt"_: return "text/vtt";
  case "htm"_:
  case "html"_: return "text/html";

  case "apng"_: return "image/apng";
  case "avif"_: return "image/avif";
  case "bmp"_: return "image/bmp";
  case "gif"_: return "image/gif";
  case "png"_: return "image/png";
  case "svg"_: return "image/svg+xml";
  case "webp"_: return "image/webp";
  case "ico"_: return "image/x-icon";
  case "tif"_: return "image/tiff";
  case "tiff"_: return "image/tiff";
  case "jpg"_:
  case "jpeg"_: return "image/jpeg";

  case "mp4"_: return "video/mp4";
  case "mpeg"_: return "video/mpeg";
  case "webm"_: return "video/webm";

  case "mp3"_: return "audio/mp3";
  case "mpga"_: return "audio/mpeg";
  case "weba"_: return "audio/webm";
  case "wav"_: return "audio/wave";

  case "otf"_: return "font/otf";
  case "ttf"_: return "font/ttf";
  case "woff"_: return "font/woff";
  case "woff2"_: return "font/woff2";

  case "7z"_: return "application/x-7z-compressed";
  case "atom"_: return "application/atom+xml";
  case "pdf"_: return "application/pdf";
  case "js"_:
  case "mjs"_: return "application/javascript";
  case "json"_: return "application/json";
  case "rss"_: return "application/rss+xml";
  case "tar"_: return "application/x-tar";
  case "xht"_:
  case "xhtml"_: return "application/xhtml+xml";
  case "xslt"_: return "application/xslt+xml";
  case "xml"_: return "application/xml";
  case "gz"_: return "application/gzip";
  case "zip"_: return "application/zip";
  case "wasm"_: return "application/wasm";
  }
}


inline bool can_compress_content_type(const std::string &content_type) {
  return (!content_type.find("text/") && content_type != "text/event-stream") ||
         content_type == "image/svg+xml" ||
         content_type == "application/javascript" ||
         content_type == "application/json" ||
         content_type == "application/xml" ||
         content_type == "application/xhtml+xml";
}

}

} // namespace httplib

#endif // HTTPLIB_MIME_HPP
