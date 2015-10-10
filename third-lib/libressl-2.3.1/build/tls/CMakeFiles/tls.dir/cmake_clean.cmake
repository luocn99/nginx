file(REMOVE_RECURSE
  "libtls.pdb"
  "libtls.a"
)

# Per-language clean rules from dependency scanning.
foreach(lang)
  include(CMakeFiles/tls.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
