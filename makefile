include $(HOME)/etc/make.setup
USERINCL=
PUBOBJS = codeutil.o utility.o sha2.o
KEYOBJS = cJSON.o myKey.o
MYLIBSO = $(TOPLIBDIR)libmykey$(BITS).so
MYLIBA = $(TOPLIBDIR)libmykey$(BITS).a
PARAM = -L$(TOPLIBDIR) -lmykey$(BITS)

all:.PHONY $(MYLIBA) myKey $(MYLIBSO) 

$(MYLIBA):$(PUBOBJS)
	$(LD) $@ $(addprefix $(TOPOBJDIR),$(PUBOBJS))

$(MYLIBSO):$(PUBOBJS)
	$(SO) $@ $(addprefix $(TOPOBJDIR),$(PUBOBJS))

myKey:$(KEYOBJS)
	$(EXE) $@ $(addprefix $(TOPOBJDIR),$(KEYOBJS)) $(PARAM)

fpr:
	sourceanalyzer -b codescan -clean
	sourceanalyzer -b codescan make
	sourceanalyzer -b codescan -scan -f $(LIBNAME).fpr

.PHONY : clean
clean:
	$(RM) $(MYLIBA)
	$(RM) $(MYLIBSO)
	$(RM) $(PUBOBJS) $(KEYOBJS)
	$(RM) $(LIBNAME).fpr
