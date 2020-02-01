FLAGS=-Wall -Werror -std=gnu99

pingc: ping_client.c
	gcc $(FLAGS) ping_client.c -o pingc

pings: ping_server.c
	gcc $(FLAGS) ping_server.c -o pings

daemon: daemon.c
	gcc $(FLAGS) daemon.c -o daemon

ruter: ruter.c
	gcc $(FLAGS) ruter.c -o ruter

daa: daemon.c
	./daemon /tmp/ac /tmp/ar /tmp/af 10

dab: daemon.c
	./daemon /tmp/bc /tmp/br /tmp/bf 20 30 40

dac: daemon.c
	./daemon /tmp/cc /tmp/cr /tmp/cf 50 60

dad: daemon.c
	./daemon /tmp/dc /tmp/dr /tmp/df 70 80 90

dae: daemon.c
	./daemon /tmp/ec /tmp/er /tmp/ef 100

ra: ruter.c
	./ruter /tmp/ar /tmp/af

rb: ruter.c
	./ruter /tmp/br /tmp/bf

rc: ruter.c
	./ruter /tmp/cr /tmp/cf

rd: ruter.c
	./ruter /tmp/dr /tmp/df

re: ruter.c
	./ruter /tmp/er /tmp/ef
