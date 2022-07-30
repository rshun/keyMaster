include ../etc/make.setup
USERINCL=
OBJDIR=../obj/
LIBDIR=../lib/
PUBOBJS = codeutil.o utility.o sha2.o cJSON.o
KEYOBJS = myKey.o
MYLIBSO = $(LIBDIR)libmykey$(BITS).so
MYLIBA = $(LIBDIR)libmykey$(BITS).a
PARAM = -L$(TOPLIBDIR) -lmykey$(BITS)

all:.PHONY $(MYLIBA) myKey

$(MYLIBA):$(PUBOBJS)
	$(LD) $@ $(addprefix $(OBJDIR),$(PUBOBJS))

$(MYLIBSO):$(PUBOBJS)
	$(SO) $@ $(addprefix $(OBJDIR),$(PUBOBJS))

myKey:$(KEYOBJS)
	$(EXE) $@ $(addprefix $(OBJDIR),$(KEYOBJS)) $(MYLIBA)

install:
	$(CP) myKey $(TOPBINDIR)
	$(CP) $(MYLIBA) $(TOPLIBDIR)
	
fpr:myKey
	sourceanalyzer -b codescan -clean
	sourceanalyzer -b codescan make
	sourceanalyzer -b codescan -scan -f $<.fpr

.PHONY : clean
clean:
	$(RM) $(MYLIBA)
	$(RM) $(MYLIBSO)
	$(RM) $(addprefix $(OBJDIR),$(PUBOBJS))
	$(RM) $(addprefix $(OBJDIR),$(KEYOBJS))
	$(RM) *.fpr
	$(RM) myKey
