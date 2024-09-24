sources = files(
  'COFFLoader.c',
  'beacon_compatibility.c',
)

coffloader_hdrs = ['../include/COFFLoader/COFFLoader.h']
coffloader_inc = include_directories('../include')
coffloader_lib = static_library('COFFLoader', sources,
  include_directories : coffloader_inc,
  install : true,
)

install_headers(coffloader_hdrs, subdir : meson.project_name())

coffloader_dep = declare_dependency(
  include_directories : coffloader_inc,
  link_with : [coffloader_lib]
)

executable('COFFLoader-bin', 'main.c',
  dependencies : [coffloader_dep],
)
