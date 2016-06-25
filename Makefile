 CC        = /usr/bin/gcc
 CC_FLAGS  = -Wall -std=gnu99 -m64 -O3 -lssl
 CC_PATHS  = 
 CC_LIBS   =

# uncomment to use the older, default GMP installation
CC_PATHS +=
CC_LIBS  +=              -lgmp

all    : attack

attack : $(wildcard *.[ch])
	@${CC} ${CC_FLAGS} ${CC_PATHS} -o ${@} $(filter %.c, ${^}) ${CC_LIBS}

clean  : 
	@rm -f core attack
