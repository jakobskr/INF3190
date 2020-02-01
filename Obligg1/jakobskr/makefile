FLAGS=-Wall -Werror -std=gnu99

pingc: ping_client.c
	gcc $(FLAGS) ping_client.c -o pingc

pings: ping_server.c
	gcc $(FLAGS) ping_server.c -o pings

daemon: daemon.c
	gcc $(FLAGS) daemon.c -o daemon
