all:
	gcc -DTESTING -Wall chacha.c encrypt.c
	echo "test message" > test.txt
	./a.out
	diff test.txt test.pt
	rm -f *.o a.out test.txt test.enc test.pt key.txt
clean:
	rm -f *.o a.out test.txt test.enc test.pt key.txt
