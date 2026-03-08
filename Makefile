OUT=bin
FLAGS=-lcrypto -lz

all: pack client

pack:
	gcc pack.c -o $(OUT)/pack $(FLAGS)
	
client:
	gcc client.c -o $(OUT)/client $(FLAGS)

clean:
	$(RM) $(OUT)/pack
	$(RM) $(OUT)/client