FLAGS=-Wall -Werror -std=gnu99

pingc: ping_client.c
	gcc $(FLAGS) ping_client.c -o pingc

pings: ping_server.c
	gcc $(FLAGS) ping_server.c -o pings

daemon: daemon.c
	gcc $(FLAGS) daemon.c -o daemon

unixc: unix_client.c
	gcc $(FLAGS) unix_client.c -o unixc

unixs: unix_server.c
	gcc $(FLAGS) unix_server.c -o unixs

epoll: epoll.c
	gcc $(FLAGS) epoll.c -o epoll

interface: interface.c
	gcc $(FLAGS) interface.c -o interface

server: server.c
	gcc $(FLAGS) server.c -o server
