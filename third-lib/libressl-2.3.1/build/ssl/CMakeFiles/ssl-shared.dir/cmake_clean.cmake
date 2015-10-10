file(REMOVE_RECURSE
  "libssl.pdb"
  "libssl.so"
  "libssl.so.37.0.0"
  "libssl.so.37"
)

# Per-language clean rules from dependency scanning.
foreach(lang)
  include(CMakeFiles/ssl-shared.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
