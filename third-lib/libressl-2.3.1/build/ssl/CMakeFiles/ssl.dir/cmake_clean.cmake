file(REMOVE_RECURSE
  "libssl.pdb"
  "libssl.a"
)

# Per-language clean rules from dependency scanning.
foreach(lang)
  include(CMakeFiles/ssl.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
