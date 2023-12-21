TARGET = fastPathSign

CC = xcrun -sdk iphoneos clang
CFLAGS = -miphoneos-version-min=15.0 -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS += -framework Foundation -framework CoreServices -framework Security -fobjc-arc $(shell pkg-config --cflags libcrypto) -Isrc/external/include
LDFLAGS += -Lsrc/external/lib -lchoma -lcrypto

$(TARGET): $(wildcard src/*.m src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	ldid -Sroothide.xml $@

clean:
	@rm -f $(TARGET)