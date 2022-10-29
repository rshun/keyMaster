
all:.PHONY default

default:
	cd util && $(MAKE) 
	cd src && $(MAKE) 

install:
	cd src && $(MAKE) install

.PHONY : clean
clean:
	cd util && $(MAKE) clean
	cd src && $(MAKE) clean
