project (
  'Yrden',

  'cpp',

  default_options: ['cpp_std=c++20'],
  version: '0.1.0',
)

if host_machine.system () != 'linux'
  warning ('Building for a non-Linux system is unlikely to succeed')
endif

subdir ('third_party')

executable (
  'yrden',

  'yrden.cc',

  dependencies: [
    cxxopts_dep,
    fmt_dep
  ]
)

subdir ('tests')