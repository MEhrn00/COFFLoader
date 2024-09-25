PROJECT = COFFLoader
VERSION = 2024-09-24.1
DESCRIPTION = Quick and dirty COFF loader (AKA Beacon Object Files). Currently can run un-modified BOF's so it can be used for testing without a CS agent running it.

prefix = /usr/local
datarootdir = $(prefix)/share
datadir = $(datarootdir)
includedir = $(prefix)/include
licensedir = $(datarootdir)/licenses

exec_prefix = $(prefix)
bindir = $(exec_prefix)/bin
libdir = $(exec_prefix)/lib
srcdir = $(dir $(realpath $(lastword $(MAKEFILE_LIST))))/src

install_libs = src/libCOFFLoader.a
install_headers = include/COFFLoader/COFFLoader.h
install_license = LICENSE.txt
install_pc = $(PROJECT).pc

install_dirs = $(DESTDIR)$(licensedir)/$(PROJECT) \
			   $(DESTDIR)$(includedir)/$(PROJECT) \
			   $(DESTDIR)$(libdir) \
			   $(DESTDIR)$(libdir)/pkgconfig

uninstall_dirs = $(DESTDIR)$(licensedir)/$(PROJECT) \
				 $(DESTDIR)$(includedir)/$(PROJECT)

RM = rm -f
INSTALL = install
MKDIR = mkdir -p
INSTALL_PROGRAM = $(INSTALL) -m 0744
INSTALL_DATA = $(INSTALL) -m 0644

define PC_TMPL
prefix=$(DESTDIR)$(prefix)
exec_prefix=$${prefix}
includedir=$${prefix}/include
libdir=$${exec_prefix}/lib

Name: $(PROJECT)
Description: $(DESCRIPTION)
Version: $(VERSION)
Cflags: -I$${includedir}
Libs: -L$${libdir}
endef

.PHONY: all clean install installdirs uninstall

all:
	$(MAKE) -C src

clean:
	$(MAKE) -C src clean
	$(RM) COFFLoader.pc

install: $(install_libs) $(install_headers) $(install_pc) | installdirs
	$(INSTALL_DATA) $(install_libs) $(DESTDIR)$(libdir)
	$(INSTALL_DATA) $(install_headers) $(DESTDIR)$(includedir)/$(PROJECT)
	$(INSTALL_DATA) $(install_license) $(DESTDIR)$(licensedir)/$(PROJECT)
	$(INSTALL_DATA) $(install_pc) $(DESTDIR)$(libdir)/pkgconfig

install-strip:
	$(MAKE) INSTALL_PROGRAM='$(INSTALL_PROGRAM) -s' install

uninstall:
	$(RM) $(addprefix $(DESTDIR)$(libdir)/,$(notdir $(install_libs)))
	$(RM) $(addprefix $(DESTDIR)$(libdir)/pkgconfig/,$(install_pc))
	$(RM) -r $(uninstall_dirs)

installdirs: | $(install_dirs)

COFFLoader.pc:
	$(file >$@,$(PC_TMPL))


$(install_libs):
	$(MAKE) -C src $(@F)

$(install_dirs): ; $(MKDIR) $@

$(install_headers):
