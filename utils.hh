#ifndef __UTILS_HH__
#define __UTILS_HH__

#include <cstring>
#include <functional>
#include <string>
#include <system_error>
#include <utility>

extern "C" char **environ;

namespace
{
template <typename MessageSupplier, typename Func, typename... Args>
  requires (std::invocable<MessageSupplier>
            && std::convertible_to<std::invoke_result_t<MessageSupplier>,
                                   std::string>
            && std::invocable<Func, Args...>)
std::invoke_result_t<Func, Args...>
check_syscall (MessageSupplier &&supplier, Func &&func, Args &&...args)
{
  std::invoke_result_t<Func, Args...> result = std::invoke<Func, Args...> (
      std::forward<Func> (func), std::forward<Args> (args)...);

  int errno_save = errno;
  if (std::cmp_less (result, 0)) [[unlikely]]
    throw std::system_error{errno_save, std::generic_category (), supplier ()};

  return result;
}

template <typename Message, typename Func, typename... Args>
  requires (!std::invocable<Message>
            && std::convertible_to<Message, std::string>
            && std::invocable<Func, Args...>)
std::invoke_result_t<Func, Args...>
check_syscall (Message message, Func &&func, Args &&...args)
{
  auto supplier = [&] { return message; };
  return check_syscall (supplier, std::forward<Func> (func),
                        std::forward<Args> (args)...);
}
}

#endif /* __UTILS_HH__ */