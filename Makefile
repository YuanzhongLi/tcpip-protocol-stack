APPS =

TEST = test/null_device.exe \
			 test/step2.exe \
			 test/step3.exe \
			 test/step4.exe \
			 test/step5.exe \
			 test/step6.exe \
			 test/step7.exe \
			 test/step8.exe \
			 test/step9.exe \
			 test/step10.exe \
			 test/step11.exe \
			 test/step12.exe \
			 test/step13.exe \
			 test/step14.exe \
			 test/step15.exe \
			 test/step16.exe \

DRIVERS = driver/null.o \
          driver/loopback.o \

OBJS = util.o \
       net.o \
			 ether.o \
			 arp.o \
			 ip.o \
			 icmp.o \
			 udp.o \

CFLAGS := $(CFLAGS) -g -W -Wall -Wno-unused-parameter -I .

ifeq ($(shell uname),Linux)
       CFLAGS := $(CFLAGS) -pthread
       TEST := $(TEST)
       DRIVERS := $(DRIVERS) driver/ether_tap_linux.o
endif

.SUFFIXES:
.SUFFIXES: .c .o

.PHONY: all clean

all: $(APPS) $(TEST)

$(APPS): % : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

$(TEST): %.exe : %.o $(OBJS) $(DRIVERS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(APPS) $(APPS:=.o) $(OBJS) $(DRIVERS) $(TEST) $(TEST:.exe=.o)
