    project (Utils C)



#----------------------- file groups ------------------------------

file (GLOB exe_srcs "list_smargo.c")
file (GLOB exe_hdrs "*.h")
file (GLOB all_srcs ${exe_srcs})

#----------------------- the executable ------------------------------

set (util_name "list_smargo")
add_executable (${util_name} ${exe_srcs} ${exe_hdrs})
target_link_libraries (${util_name} ${libusb_link} ${rt_link} ${setupapi_link} ${ole32_link} ${shell32_link} ${pthread_link} ${dl_link})
#----------------------- printout resume -----------------------------

message (STATUS "Utils: operating system: ${OSCamOperatingSystem}")
message (STATUS "Utils: target system: ${CS_TARGET}")
if(STATIC_LIBUSB EQUAL 0)
   message (STATUS "Utils: You selected to disable static libusb system libusb used")
endif(STATIC_LIBUSB EQUAL 0)
if(STATICLIBUSB AND NOT LIBUSBDIR)
    message (STATUS " utils use static libusb functions")
 else(STATICLIBUSB AND NOT LIBUSBDIR)
   if (LIBUSBDIR AND STATIC_LIBUSB EQUAL 0)
      message(STATUS " utils use system libusb from selected LIBUSBDIR functions")
   elseif (LIBUSBDIR AND STATIC_LIBUSB EQUAL 1)
      message(STATUS " utils use static libusb from selected LIBUSBDIR functions")
   elseif(LIBUSBDIR AND NOT STATIC_LIBUSB)
      message(STATUS " utils use system libusb from selected LIBUSBDIR functions")
   elseif(NOT LIBUSBDIR AND NOT STATIC_LIBUSB)
      message(STATUS " utils use system libusb functions")
   endif(LIBUSBDIR AND STATIC_LIBUSB EQUAL 0)
 endif(STATICLIBUSB AND NOT LIBUSBDIR)
message (STATUS "")

