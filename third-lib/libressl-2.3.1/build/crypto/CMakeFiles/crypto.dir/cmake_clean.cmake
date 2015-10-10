file(REMOVE_RECURSE
  "libcrypto.pdb"
  "libcrypto.a"
)

# Per-language clean rules from dependency scanning.
foreach(lang)
  include(CMakeFiles/crypto.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
