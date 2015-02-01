.SUFFIX : .c .o

CC = sbs -e gcc
INC = -I../include/
LIBS = -lcert-svc
CFLAGS = -g $(INC)

TARGET = \
		 store_test \
		 delete_test \
		 extract_test \
		 extract_test_pfx \
		 search_test \
		 verify_test \
		 verify_sig \
		 mem_test

all: $(TARGET)

$(TARGET): %: %.c
	$(CC) -o $@ $< $(CFLAGS) $(LIBS)

clean:
	rm -rf *.o $(TARGET) *~ *core
