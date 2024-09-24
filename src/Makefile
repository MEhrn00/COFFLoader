CC=x86_64-w64-mingw32-gcc
AR=x86_64-w64-mingw32-ar

sources := COFFLoader.c beacon_compatibility.c main.c
objs := $(sources:.c=.o)
deps := $(objs:.o=.d)

includes := ../include
CFLAGS+=-Wall -g

override CFLAGS+=$(addprefix -I,$(includes))

depflags = -MT $@ -MMD -MP -MF $*.d

COMPILE.c = $(CC) $(depflags) $(CFLAGS) $(CPPFLAGS) $(TARGET_ARCH) -c

.PHONY: default all clean
all: COFFLoader.exe libCOFFLoader.a

libCOFFLoader.a: libCOFFLoader.a(COFFLoader.o beacon_compatibility.o)
COFFLoader.exe: main.o libCOFFLoader.a

clean:
	$(RM) COFFLoader.exe libCOFFLoader.a $(objs) $(deps)

%.exe: %.o
	$(LINK.o) $^ $(LOADLIBES) $(LDLIBS) -o $@

%.o: %.c
%.o: %.c %.d
	$(COMPILE.c) $(OUTPUT_OPTION) $<

(%): % ;
%.a: ; $(AR) $(ARFLAGS) $@ $?

$(deps):
-include $(deps)
