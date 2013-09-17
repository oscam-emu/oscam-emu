project (cscrypt)
if (OSCamOperatingSystem MATCHES "Mac OS X" AND SWVER GREATER 10.5 AND HAVE_LIBCRYPTO)
file (GLOB cscrypt_mac "bn*" "mem*" "aes*" "sha1*")
file (GLOB cscrypt_srcs "*.c")
list(REMOVE_ITEM cscrypt_srcs ${cscrypt_mac})
file (GLOB cscrypt_hdrs "*.h")
list(REMOVE_ITEM cscrypt_hdrs ${cscrypt_mac})
else (OSCamOperatingSystem MATCHES "Mac OS X" AND SWVER GREATER 10.5 AND HAVE_LIBCRYPTO)
file (GLOB cscrypt_srcs "*.c")
file (GLOB cscrypt_hdrs "*.h")
endif (OSCamOperatingSystem MATCHES "Mac OS X" AND SWVER GREATER 10.5 AND HAVE_LIBCRYPTO)

set (lib_name "cscrypt")

add_library (${lib_name} STATIC ${cscrypt_srcs} ${cscrypt_hdrs})

