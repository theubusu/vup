OUT=bin
FLAGS=-lcrypto -lz

all: pack client

pack:
	gcc pack.c -o $(OUT)/pack $(FLAGS)
	
client:
	gcc client.c -o $(OUT)/client $(FLAGS)

n_vup:
	gcc n_vup.c -o $(OUT)/n_vup

n_ezcrypt:
	gcc n_ezcrypt.c -o $(OUT)/n_ezcrypt

clean:
	$(RM) $(OUT)/pack
	$(RM) $(OUT)/client
	$(RM) $(OUT)/n_vup