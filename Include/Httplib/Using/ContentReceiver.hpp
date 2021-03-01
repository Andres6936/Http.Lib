// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_CONTENTRECEIVER_HPP
#define HTTPLIB_CONTENTRECEIVER_HPP

#include <functional>

namespace httplib {

using ContentReceiver =
std::function<bool(const char *data, size_t data_length)>;

} // namespace httplib

#endif // HTTPLIB_CONTENTRECEIVER_HPP
