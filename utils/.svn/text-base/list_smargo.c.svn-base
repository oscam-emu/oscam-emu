/*
 * libusb example program to list devices on the bus
 * Copyright (C) 2007 Daniel Drake <dsd@gentoo.org>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <string.h>
#include "../globals.h"
#include "../csctapi/ifd_smartreader_types.h"

#if defined(__FreeBSD__)
#include <libusb.h>
#else
#include <libusb-1.0/libusb.h>
#endif

static void smartreader_check_endpoint(libusb_device *usb_dev, libusb_device_handle *handle)
{
	struct libusb_device_descriptor usbdesc;
	struct libusb_config_descriptor *configDesc;
	int32_t ret;
	int32_t j,k,l;
	uint32_t m;
	uint8_t tmpEndpointAddress;
	int32_t nb_endpoint_ok;
	int32_t busid, devid;
  unsigned char iserialbuffer[128], iproductbuffer[128];
  char *productptr = (char *)iproductbuffer;
	
	nb_endpoint_ok=0;
	
	ret = libusb_get_device_descriptor(usb_dev, &usbdesc);
	if (ret < 0) {
		printf("Smartreader : couldn't read device descriptor, assuming this is not a smartreader");
		return;
	}
	if (usbdesc.bNumConfigurations) {
		ret=libusb_get_active_config_descriptor(usb_dev,&configDesc);
		if(ret) {
			printf("Smartreader : couldn't read config descriptor , assuming this is not a smartreader");
			return;
		}
		for(m = 0; m < sizeof(reader_types)/sizeof(struct s_reader_types); ++m){
			nb_endpoint_ok = 0;
			for(j=0; j<configDesc->bNumInterfaces; j++) {
				for(k=0; k<configDesc->interface[j].num_altsetting; k++) {
					for(l=0; l<configDesc->interface[j].altsetting[k].bNumEndpoints; l++) {
						tmpEndpointAddress=configDesc->interface[j].altsetting[k].endpoint[l].bEndpointAddress;
						if((tmpEndpointAddress == reader_types[m].in_ep || tmpEndpointAddress == reader_types[m].out_ep)){
							nb_endpoint_ok++;
						}
					}
				}
			}
			if(nb_endpoint_ok == 2){
				busid=libusb_get_bus_number(usb_dev);
        devid=libusb_get_device_address(usb_dev);
        memset(iserialbuffer, 0, sizeof(iserialbuffer));
        memset(iproductbuffer, 0, sizeof(iproductbuffer));
        libusb_get_string_descriptor_ascii(handle,usbdesc.iSerialNumber,iserialbuffer,sizeof(iserialbuffer));
        libusb_get_string_descriptor_ascii(handle,usbdesc.iProduct,iproductbuffer,sizeof(iproductbuffer));
        printf("bus %03d, device %03d : %04x:%04x %s (type=%s, in_ep=%02x, out_ep=%02x; insert in oscam.server 'device = %s%sSerial:%s')\n",
        	busid, devid,
        	usbdesc.idVendor, usbdesc.idProduct, strlen(productptr)>0?productptr:"Smartreader",
        	reader_types[m].name, reader_types[m].in_ep, reader_types[m].out_ep,
        	strcmp(reader_types[m].name, "SR")?reader_types[m].name:"",strcmp(reader_types[m].name, "SR")?";":"", iserialbuffer
        );
      }
		}
	}
}

static void print_devs(libusb_device **devs)
{
  libusb_device *dev;
  libusb_device_handle *handle;
  int32_t i = 0;
  int32_t ret;

  while ((dev = devs[i++]) != NULL) {
    struct libusb_device_descriptor usbdesc;
    int32_t r = libusb_get_device_descriptor(dev, &usbdesc);
    if (r < 0) {
      fprintf(stderr, "failed to get device descriptor");
      return;
    }
    if (usbdesc.idVendor==0x0403 && (usbdesc.idProduct==0x6001 || usbdesc.idProduct==0x6011)) {
      ret=libusb_open(dev,&handle);
      if (ret) {
        printf ("couldn't open device %03d:%03d\n", libusb_get_bus_number(dev), libusb_get_device_address(dev));
        continue;
      }
      // check for smargo endpoints.
      smartreader_check_endpoint(dev, handle);

      libusb_close(handle);
    }
  }
}

int32_t main(void)
{
  libusb_device **devs;
  int32_t r;
  ssize_t cnt;

  r = libusb_init(NULL);
  if (r < 0)
    return r;

  printf("Looking for smartreader compatible devices...\n");

  cnt = libusb_get_device_list(NULL, &devs);
  if (cnt < 0)
    return (int32_t) cnt;

  print_devs(devs);
  libusb_free_device_list(devs, 1);

  libusb_exit(NULL);

  return 0;
}

