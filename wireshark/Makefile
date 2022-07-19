.PHONY: install clean
CC ?= gcc
CCFLAGS ?= -I/usr/include/lua5.2
INSTALL_DIR ?= ~/.local/lib/wireshark/plugins
EXTENSION ?= so

install: libcompat.$(EXTENSION)
	printf 'local package_loc = "$(shell pwd)/libcompat.$(EXTENSION)"' > '$(INSTALL_DIR)/hop.lua'
	cat hop.lua >> '$(INSTALL_DIR)/hop.lua'
clean:
	rm -f *.dynlib *.dll *.lib *.a *.so

# Note that we can't use $^ for the prerequisites because gcc strips the .a
libcompat.so: libdecrypt.a compatibility.c
	$(CC) $(CCFLAGS) -pthread -shared -o $@ -fPIC compatibility.c libdecrypt.a $(LIBLUA)
libcompat.dynlib: libdecrypt.a compatibility.c
	$(CC) $(CCFLAGS) -pthread -shared -o $@ -fPIC compatibility.c libdecrypt.a $(LIBLUA)
libcompat.dll: libdecrypt.lib compatibility.c
	$(CC) $(CCFLAGS) -shared -o $@ -fPIC compatibility.c libdecrypt.lib $(LIBLUA)
libdecrypt.%: decrypt.go
	go build -o $@ -buildmode=c-archive $<
