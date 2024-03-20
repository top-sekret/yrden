#include <filesystem>

#include <fmt/format.h>
#include <unistd.h>

int
main ()
{
  std::string domainname (HOST_NAME_MAX, '\0');
  getdomainname (domainname.data (), HOST_NAME_MAX);

  std::string hostname (HOST_NAME_MAX, '\0');
  gethostname (hostname.data (), HOST_NAME_MAX);

  auto working_directory = std::filesystem::current_path ();

  std::size_t environ_count = 0;
  while (environ[environ_count])
    ++environ_count;

  fmt::print ("Absolute working directory: {}\n"
              "Domain name: {}\n"
              "Host name: {}\n"
              "Working directory: {}\n"
              "Environment: ({} variables)\n",
              std::filesystem::absolute (working_directory).native (),
              domainname, hostname, working_directory.native (),
              environ_count);

  for (auto it = environ; *it; ++it)
    fmt::print ("{}\n", *it);
}