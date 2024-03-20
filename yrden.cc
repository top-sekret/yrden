#ifndef _GNU_SOURCE
#define _GNU_SOURCE // for unshare
#endif

#include <array>
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include <cxxopts.hpp>
#include <fcntl.h>
#include <fmt/format.h>
#include <sched.h>
#include <sys/mount.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "utils.hh"

#ifndef O_DIRECTORY
#define O_DIRECTORY 0
#endif

extern "C" char **environ;

namespace
{
void
write_file (const char *path, std::string_view contents)
{
  int fd
      = check_syscall ([&] { return fmt::format ("open({}) failed", path); },
                       open, path, O_WRONLY);
  check_syscall (
      [&] {
        return fmt::format ("write({}, <{} bytes>) failed", path,
                            contents.size ());
      },
      write, fd, contents.data (), contents.size ());
  check_syscall ([&] { return fmt::format ("close({}) failed", path); }, close,
                 fd);
}

void
bind_mount (const std::vector<std::pair<std::string, std::string>> &binds)
{
  for (const auto &[src, dest] : binds)
    check_syscall (
        [&] {
          return fmt::format ("mount({}, {}, --rbind) failed", src, dest);
        },
        mount, src.c_str (), dest.c_str (), nullptr, MS_BIND | MS_REC,
        nullptr);
}

void
change_dir (const std::string &name)
{
  check_syscall ([&] { return fmt::format ("chdir({}) failed", name); }, chdir,
                 name.c_str ());
}

void
change_dir_fd (int fd, const std::string &name)
{
  check_syscall ([&] { return fmt::format ("chdir({}) failed", name); },
                 fchdir, fd);
}

void
change_root (const std::string &name)
{
  check_syscall ([&] { return fmt::format ("chroot({}) failed", name); },
                 chroot, name.c_str ());
}

void
do_unshare ()
{
  gid_t old_gid = getgid ();
  uid_t old_uid = getuid ();

  check_syscall ("unshare(CLONE_NEWNS | CLONE_NEWUSER) failed", unshare,
                 CLONE_NEWCGROUP | CLONE_NEWIPC | CLONE_NEWNET | CLONE_NEWNS
                     | CLONE_NEWUSER | CLONE_NEWUTS);
  write_file ("/proc/self/uid_map", fmt::format ("0 {} 1", old_uid));
  constexpr std::string_view deny{"deny"};
  write_file ("/proc/self/setgroups", deny);
  write_file ("/proc/self/gid_map", fmt::format ("0 {} 1", old_gid));
}

[[noreturn]] void
execute (const std::vector<std::string> &command, const char *alias,
         const char *const *new_environ)
{
  std::vector<const char *> argv (command.size () + 1);
  argv[0] = alias ? alias : command.front ().c_str ();
  for (std::size_t i = 1; i < command.size (); ++i)
    argv[i] = command[i].c_str ();
  argv.back () = nullptr;

  check_syscall (
      [&] { return fmt::format ("execvpe({}) failed", command.front ()); },
      execvpe, command.front ().c_str (),
      const_cast<char *const *> (argv.data ()),
      const_cast<char *const *> (new_environ));

#ifdef __GNUC__
  __builtin_unreachable ();
#endif
  std::terminate ();
}

int
open_directory (const std::string &path)
{
  return check_syscall (
      [&] {
        return fmt::format (
            "open({}, O_RDONLY | O_DIRECTORY | O_CLOEXEC) failed", path);
      },
      open, path.c_str (), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
}

template <bool NoRoot>
std::vector<std::pair<std::string, std::string>>
parse_bind_mounts (const std::string &root,
                   const std::vector<std::string> &specs)
{
  std::vector<std::pair<std::string, std::string>> result (specs.size ());
  for (std::size_t i = 0; i < specs.size (); ++i)
    {
      auto index = specs[i].find (':');

      if (index != std::string_view::npos)
        result[i]
            = {specs[i].substr (0, index),
               fmt::format ("{}/{}", root,
                            std::string_view{specs[i]}.substr (index + 1))};
      else
        {
          if constexpr (NoRoot)
            throw cxxopts::exceptions::exception{
                "When not using the -r/--root options, all arguments to "
                "-b/--bind must contain a colon"};
          else
            result[i] = {specs[i], fmt::format ("{}/{}", root, specs[i])};
        }
    }
  return result;
}

void
set_domain_name (const std::string &str)
{
  check_syscall ([&] { return fmt::format ("setdomainname({}) failed", str); },
                 setdomainname, str.data (), str.size ());
}

void
set_host_name (const std::string &str)
{
  check_syscall ([&] { return fmt::format ("sethostname({}) failed", str); },
                 sethostname, str.data (), str.size ());
}
}

int
main (int argc, char **argv) noexcept
{
  try
    {
      cxxopts::Options options{"yrden", "A simple container for applications"};
      options.add_options ()
          // -a --alias
          ("a,alias", "Set the alias (argv[0]) of the newly spawned process",
           cxxopts::value<std::string> (), "ALIAS")
          // -b --bind
          ("b,bind",
           "Bind mount a share in the container (note: using the abbreviated "
           "form requires specifying -r/--root)",
           cxxopts::value<std::vector<std::string>> (), "SRC[:DEST]")
          // -c --command <positional>
          ("c,command", "Command to run",
           cxxopts::value<std::vector<std::string>> ())
          // -d --domainname
          ("d,domainname", "Change the NIS domain name in the container",
           cxxopts::value<std::string> (), "DOMAINNAME")
          // -e --env
          ("e,env",
           "Set the environment variable KEY to value VALUE, or remove it if "
           "no VALUE is given",
           cxxopts::value<std::vector<std::string>> (), "KEY[=VALUE]")
          // -E --clear-env
          ("E,clear-env", "Do not inherit environment variables")
          // -h --help
          ("h,help", "Print this help text")
          // -H --hostname
          ("H,hostname", "Change the host name in the container",
           cxxopts::value<std::string> (), "HOSTNAME")
          // -r --root
          ("r,root", "Specify the new root of the mapping",
           cxxopts::value<std::string> ())
          // -w --workdir
          ("w,workdir", "Specify the new working directory",
           cxxopts::value<std::string> ())
          // -W --workdir-outside
          ("W,workdir-outside",
           "Specify the new working directory in the terms of the old "
           "filesystem root (outside container)",
           cxxopts::value<std::string> ());
      options.parse_positional ("command");
      auto result = options.parse (argc, argv);

      if (result.count ("help"))
        {
          fmt::print (stdout, "{}\n", options.help ());
          return 0;
        }

      const std::string *root = nullptr;

      // Parse binds
      std::vector<std::pair<std::string, std::string>> binds{};
      if (result.count ("root"))
        {
          root = &result["root"].as<std::string> ();

          if (result.count ("bind"))
            binds = parse_bind_mounts<false> (
                *root, result["bind"].as<std::vector<std::string>> ());
        }
      else
        {
          if (result.count ("bind"))
            binds = parse_bind_mounts<true> (
                {}, result["bind"].as<std::vector<std::string>> ());
        }

      const std::string *workdir = nullptr;
      int workdir_fd = -1;

      // Working directory outside container
      if (result.count ("workdir-outside"))
        {
          if (result.count ("workdir")) [[unlikely]]
            throw cxxopts::exceptions::exception{
                "Cannot use -w/--workdir and -W/--workdir-outside "
                "simultaneously!\n"};

          workdir = &result["workdir-outside"].as<std::string> ();
          workdir_fd = open_directory (*workdir);
        }

      do_unshare ();

      bind_mount (binds);

      // Root/working directory
      if (root)
        change_root (*root);

      if (workdir)
        change_dir_fd (workdir_fd, *workdir);
      else if (result.count ("workdir"))
        change_dir (result["workdir"].as<std::string> ());

      // Host/domain name
      if (result.count ("hostname"))
        set_host_name (result["hostname"].as<std::string> ());
      if (result.count ("domainname"))
        set_domain_name (result["domainname"].as<std::string> ());

      // Environment
      const char **new_environ = const_cast<const char **> (environ);
      std::vector<const char *> new_environ_vec{};
      if (result.count ("env") || result.count ("clear-env"))
        {
          if (!result.count ("clear-env"))
            for (char **iter = environ; *iter; ++iter)
              new_environ_vec.push_back (*iter);
          if (result.count ("env"))
            for (const auto &val :
                 result["env"].as<std::vector<std::string>> ())
              {
                auto index = val.find ('=');

                if (index != std::string::npos)
                  {
                    std::string_view key{val.begin (),
                                         val.begin () + index + 1};
                    std::erase_if (new_environ_vec, [&] (const char *s) {
                      std::string_view sv{s};
                      return sv.starts_with (key);
                    });

                    new_environ_vec.push_back (val.c_str ());
                  }
                else
                  std::erase_if (new_environ_vec, [&] (const char *s) {
                    std::string_view sv{s};
                    if (sv.starts_with (val))
                      {
                        assert (sv.size () > val.size ());
                        return sv[val.size ()] == '=';
                      }
                    else
                      return false;
                  });
              }
          new_environ_vec.push_back (nullptr);

          new_environ = new_environ_vec.data ();
        }

      const char *alias = result.count ("alias")
                              ? result["alias"].as<std::string> ().c_str ()
                              : nullptr;
      const auto &command = result["command"].as<std::vector<std::string>> ();
      execute (command, alias, new_environ);

#ifdef __GNUC__
      __builtin_unreachable ();
#endif
      std::terminate ();
    }
  catch (const cxxopts::exceptions::exception &ex)
    {
      fmt::print (stderr,
                  "Usage error: {}\nUse {} --help for more information.\n",
                  ex.what (), argv[0]);
      return 2;
    }
  catch (const std::exception &ex)
    {
      fmt::print (stderr, "Error: {}\n", ex.what ());
      return 1;
    }
}