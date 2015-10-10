file(REMOVE_RECURSE
  "libcrypto.pdb"
  "libcrypto.so"
  "libcrypto.so.36.0.0"
  "libcrypto.so.36"
)

# Per-language clean rules from dependency scanning.
foreach(lang)
  include(CMakeFiles/crypto-shared.dir/cmake_clean_${lang}.cmake OPTIONAL)
endforeach()
