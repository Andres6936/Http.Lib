// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_MULTIPARTFORMDATA_HPP
#define HTTPLIB_MULTIPARTFORMDATA_HPP

namespace httplib {

struct MultipartFormData {
  std::string name;
  std::string content;
  std::string filename;
  std::string content_type;
};

using MultipartFormDataItems = std::vector<MultipartFormData>;
using MultipartFormDataMap = std::multimap<std::string, MultipartFormData>;
using MultipartContentHeader =
std::function<bool(const MultipartFormData &file)>;

} // namespace httplib

#endif // HTTPLIB_MULTIPARTFORMDATA_HPP
