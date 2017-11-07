all : multi_block

multi_block: avltree.o main.o
	g++ -g -o multi_block main.o avltree.o -lnetfilter_queue

avltree.o: avltree.c avltree.h
	g++ -g -c -o avltree.o avltree.c

main.o: main.cpp avltree.h
	g++ -g -c -o main.o main.cpp

clean:
	rm -f multi_block
	rm -f *.o

