CC = clang

CFLAGS = -I../common -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path) -miphoneos-version-min=15.0 -Wno-deprecated-declarations -fno-stack-check -D_FORTIFY_SOURCE=0 -O2
CFLAGS += -nostdlib -L. -lc # -nostdlib links no default libs, so undefined symbols are caught at build time
LDFLAGS = -Xlinker -add_split_seg_info -Wl,-dylinker -Wl,-e,_DYLD_HOOK_ENTRY
FILES = $(wildcard src/*.c src/*.S)

all: dyldhook

dyldhook: $(FILES)
	$(CC) -arch arm64 $(CFLAGS) $(LDFLAGS) -o $@ $^
	@ldid -S $@
	
clean:
	@rm -f dyldhook
