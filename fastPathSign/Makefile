TARGET = fastPathSign

CC = xcrun -sdk iphoneos clang
CFLAGS = -miphoneos-version-min=15.0 -isysroot $(shell xcrun --sdk iphoneos --show-sdk-path)

CFLAGS += -framework Foundation -framework CoreServices -framework Security -fobjc-arc $(shell pkg-config --cflags libcrypto) -I../common -I../common/Templates
LDFLAGS += -L../common/lib -lchoma -lcrypto

$(TARGET): $(wildcard src/*.m src/*.c)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^
	ldid -Sroothide.xml $@

clean:
	@rm -f $(TARGET)