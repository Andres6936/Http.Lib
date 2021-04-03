// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_MULTIPARTFORMDATAPARSER_HPP
#define HTTPLIB_MULTIPARTFORMDATAPARSER_HPP

namespace httplib {

namespace detail {


class MultipartFormDataParser {
public:
  MultipartFormDataParser() = default;

  void set_boundary(std::string &&boundary) { boundary_ = boundary; }

  bool is_valid() const { return is_valid_; }

  bool parse(const char *buf, size_t n, const ContentReceiver &content_callback,
      const MultipartContentHeader &header_callback) {

    static const std::regex re_content_disposition(
        "^Content-Disposition:\\s*form-data;\\s*name=\"(.*?)\"(?:;\\s*filename="
        "\"(.*?)\")?\\s*$",
        std::regex_constants::icase);
    static const std::string dash_ = "--";
    static const std::string crlf_ = "\r\n";

    buf_.append(buf, n); // TODO: performance improvement

    while (!buf_.empty()) {
      switch (state_) {
      case 0: { // Initial boundary
        auto pattern = dash_ + boundary_ + crlf_;
        if (pattern.size() > buf_.size()) { return true; }
        auto pos = buf_.find(pattern);
        if (pos != 0) { return false; }
        buf_.erase(0, pattern.size());
        off_ += pattern.size();
        state_ = 1;
        break;
      }
      case 1: { // New entry
        clear_file_info();
        state_ = 2;
        break;
      }
      case 2: { // Headers
        auto pos = buf_.find(crlf_);
        while (pos != std::string::npos) {
          // Empty line
          if (pos == 0) {
            if (!header_callback(file_)) {
              is_valid_ = false;
              return false;
            }
            buf_.erase(0, crlf_.size());
            off_ += crlf_.size();
            state_ = 3;
            break;
          }

          static const std::string header_name = "content-type:";
          const auto header = buf_.substr(0, pos);
          if (start_with_case_ignore(header, header_name)) {
            file_.content_type = trim_copy(header.substr(header_name.size()));
          } else {
            std::smatch m;
            if (std::regex_match(header, m, re_content_disposition)) {
              file_.name = m[1];
              file_.filename = m[2];
            }
          }

          buf_.erase(0, pos + crlf_.size());
          off_ += pos + crlf_.size();
          pos = buf_.find(crlf_);
        }
        if (state_ != 3) { return true; }
        break;
      }
      case 3: { // Body
        {
          auto pattern = crlf_ + dash_;
          if (pattern.size() > buf_.size()) { return true; }

          auto pos = find_string(buf_, pattern);

          if (!content_callback(buf_.data(), pos)) {
            is_valid_ = false;
            return false;
          }

          off_ += pos;
          buf_.erase(0, pos);
        }
        {
          auto pattern = crlf_ + dash_ + boundary_;
          if (pattern.size() > buf_.size()) { return true; }

          auto pos = buf_.find(pattern);
          if (pos != std::string::npos) {
            if (!content_callback(buf_.data(), pos)) {
              is_valid_ = false;
              return false;
            }

            off_ += pos + pattern.size();
            buf_.erase(0, pos + pattern.size());
            state_ = 4;
          } else {
            if (!content_callback(buf_.data(), pattern.size())) {
              is_valid_ = false;
              return false;
            }

            off_ += pattern.size();
            buf_.erase(0, pattern.size());
          }
        }
        break;
      }
      case 4: { // Boundary
        if (crlf_.size() > buf_.size()) { return true; }
        if (buf_.compare(0, crlf_.size(), crlf_) == 0) {
          buf_.erase(0, crlf_.size());
          off_ += crlf_.size();
          state_ = 1;
        } else {
          auto pattern = dash_ + crlf_;
          if (pattern.size() > buf_.size()) { return true; }
          if (buf_.compare(0, pattern.size(), pattern) == 0) {
            buf_.erase(0, pattern.size());
            off_ += pattern.size();
            is_valid_ = true;
            state_ = 5;
          } else {
            return true;
          }
        }
        break;
      }
      case 5: { // Done
        is_valid_ = false;
        return false;
      }
      }
    }

    return true;
  }

private:
  void clear_file_info() {
    file_.name.clear();
    file_.filename.clear();
    file_.content_type.clear();
  }

  bool start_with_case_ignore(const std::string &a,
      const std::string &b) const {
    if (a.size() < b.size()) { return false; }
    for (size_t i = 0; i < b.size(); i++) {
      if (::tolower(a[i]) != ::tolower(b[i])) { return false; }
    }
    return true;
  }

  bool start_with(const std::string &a, size_t off,
      const std::string &b) const {
    if (a.size() - off < b.size()) { return false; }
    for (size_t i = 0; i < b.size(); i++) {
      if (a[i + off] != b[i]) { return false; }
    }
    return true;
  }

  size_t find_string(const std::string &s, const std::string &pattern) const {
    auto c = pattern.front();

    size_t off = 0;
    while (off < s.size()) {
      auto pos = s.find(c, off);
      if (pos == std::string::npos) { return s.size(); }

      auto rem = s.size() - pos;
      if (pattern.size() > rem) { return pos; }

      if (start_with(s, pos, pattern)) { return pos; }

      off = pos + 1;
    }

    return s.size();
  }

  std::string boundary_;

  std::string buf_;
  size_t state_ = 0;
  bool is_valid_ = false;
  size_t off_ = 0;
  MultipartFormData file_;
};

template <typename SToken, typename CToken, typename Content>
bool process_multipart_ranges_data(const Request &req, Response &res,
    const std::string &boundary,
    const std::string &content_type,
    SToken stoken, CToken ctoken,
    Content content) {
  for (size_t i = 0; i < req.ranges.size(); i++) {
    ctoken("--");
    stoken(boundary);
    ctoken("\r\n");
    if (!content_type.empty()) {
      ctoken("Content-Type: ");
      stoken(content_type);
      ctoken("\r\n");
    }

    auto offsets = get_range_offset_and_length(req, res.body.size(), i);
    auto offset = offsets.first;
    auto length = offsets.second;

    ctoken("Content-Range: ");
    stoken(make_content_range_header_field(offset, length, res.body.size()));
    ctoken("\r\n");
    ctoken("\r\n");
    if (!content(offset, length)) { return false; }
    ctoken("\r\n");
  }

  ctoken("--");
  stoken(boundary);
  ctoken("--\r\n");

  return true;
}

template <typename T>
inline bool write_multipart_ranges_data(Stream &strm, const Request &req,
    Response &res,
    const std::string &boundary,
    const std::string &content_type,
    const T &is_shutting_down) {
  return process_multipart_ranges_data(
      req, res, boundary, content_type,
      [&](const std::string &token) { strm.write(token); },
      [&](const char *token) { strm.write(token); },
      [&](size_t offset, size_t length) {
        return write_content(strm, res.content_provider_, offset, length,
            is_shutting_down);
      });
}

inline bool make_multipart_ranges_data(const Request &req, Response &res,
    const std::string &boundary,
    const std::string &content_type,
    std::string &data) {
  return process_multipart_ranges_data(
      req, res, boundary, content_type,
      [&](const std::string &token) { data += token; },
      [&](const char *token) { data += token; },
      [&](size_t offset, size_t length) {
        if (offset < res.body.size()) {
          data += res.body.substr(offset, length);
          return true;
        }
        return false;
      });
}


inline size_t
get_multipart_ranges_data_length(const Request &req, Response &res,
    const std::string &boundary,
    const std::string &content_type) {
  size_t data_length = 0;

  process_multipart_ranges_data(
      req, res, boundary, content_type,
      [&](const std::string &token) { data_length += token.size(); },
      [&](const char *token) { data_length += strlen(token); },
      [&](size_t /*offset*/, size_t length) {
        data_length += length;
        return true;
      });

  return data_length;
}


}

} // namespace httplib

#endif // HTTPLIB_MULTIPARTFORMDATAPARSER_HPP
