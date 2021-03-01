// Joan Andrés (@Andres6936) Github.

#ifndef HTTPLIB_TASKQUEUE_HPP
#define HTTPLIB_TASKQUEUE_HPP

namespace httplib {


class TaskQueue {
public:
  TaskQueue() = default;
  virtual ~TaskQueue() = default;

  virtual void enqueue(std::function<void()> fn) = 0;
  virtual void shutdown() = 0;

  virtual void on_idle(){};
};


} // namespace httplib

#endif // HTTPLIB_TASKQUEUE_HPP
