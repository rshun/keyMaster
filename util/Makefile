include ../etc/make.setup

ifeq ($(OSNAME),Linux)
	BINDIR=$(PROJECTHOME)/bin/
	OBJDIR=$(PROJECTHOME)/obj/
	LIBDIR=$(PROJECTHOME)/lib/
	LIBNAME=mykey$(BITS)
else ifeq ($(OSNAME),Windows)
	BINDIR:=$(PROJECTHOME)\\bin\\
	OBJDIR:=$(PROJECTHOME)\\obj\\
	LIBDIR:=$(PROJECTHOME)\\lib\\
	LIBNAME:=mykey$(BITS)
endif

SOURCE=$(wildcard *.c)
PUBOBJS = $(patsubst %.c,%.o,$(SOURCE))
MYLIB=$(LIBDIR)lib$(LIBNAME).a

.c.o:
	$(CC) $(EXECOMPILE) -fPIC -o $(OBJDIR)$*.o $*.c

all:$(MYLIB)

$(MYLIB):$(PUBOBJS)
	$(LD) $@ $(addprefix $(OBJDIR),$(PUBOBJS))

.PHONY : clean
clean:
ifeq ($(OSNAME),Windows)
	$(RM) $(addprefix $(OBJDIR),$(PUBOBJS)) 2>NUL
	$(RM) $(MYLIB) 2>NUL
else
	$(RM) $(addprefix $(OBJDIR),$(PUBOBJS))
	$(RM) $(MYLIB)
endif

