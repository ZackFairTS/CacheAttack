 CC        = /usr/bin/gcc
 CC_FLAGS  = -Wall -std=gnu99 -m64 -O3 -lssl
 CC_PATHS  = 
 CC_LIBS   =

# uncomment to use the older, default GMP installation
CC_PATHS +=
CC_LIBS  +=              -lgmp

# uncomment to use the newer, bespoke GMP installation
# CC_PATHS += -I/usr/local/include/ 
# CC_PATHS += -L/usr/local/lib/
# CC_LIBS  += -Wl,-limp

# uncomment to use the bespoke (probably newer) OpenSSL installation
# CC_PATHS += -I ~page/local/linux.x86_64/openssl-1.0.1m/include/
# CC_PATHS += -L ~page/local/linux.x86_64/openssl-1.0.1m/lib/
# CC_LIBS  += -Wl,-Bstatic -lcrypto -Wl,-Bdynamic

# uncomment to use the default (probably older) OpenSSL installation
CC_PATHS += -I /usr/lib/x86_64-linux-gnu/
CC_PATHS += -L /usr/lib/x86_64-linux-gnu/
CC_LIBS  +=              -lcrypto

all    : attack

attack : $(wildcard *.[ch])
	@${CC} ${CC_FLAGS} ${CC_PATHS} -o ${@} $(filter %.c, ${^}) ${CC_LIBS}

clean  : 
	@rm -f core attack
