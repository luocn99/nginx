file(REMOVE_RECURSE
  "libtls.pdb"
  "libtls.so"
  "libtls.so.9.0.0"
  "libtls.so.9"
)

# Per-language clean rules from dependency scanning.
foreach(lang)
  include(CMakeFiles/tls-shared.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
