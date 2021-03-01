// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_PROGRESS_HPP
#define HTTPLIB_PROGRESS_HPP

#include <functional>

namespace httplib {

using Progress = std::function<bool(uint64_t current, uint64_t total)>;

} // namespace httplib

#endif // HTTPLIB_PROGRESS_HPP
