#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/un.h>
#include <sys/types.h>
#include <inttypes.h>
#include <sys/epoll.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>
#include <sys/socket.h>
#include <net/if.h>
#include <sys/ioctl.h>
#include <time.h>

#define PADDING 32 - 2
#define PORT PADDING - 14
#define SEQ_NUMBER PORT - 16
#define PAYLOAD_LENGTH 1492
#define MAX_EVENTS 10
#define WINDOW_SIZE 10
#define new_min(x,y) ((x) <= (y)) ? (x) : (y)

struct send_list {
	struct file_tp2 *file;
	time_t last_ack;
	struct send_list *next;
};


struct file_tp2 {
	unsigned char mip_addr;
	uint16_t port;
	uint16_t file_length;
	uint win_low;
	uint win_high;
	uint tot_pack;
	uint recv_ack;
	uint last_packet_length;
	uint padding;
	struct miptp_packet *packets[];
};

struct miptp_packet {
	uint32_t header;
	unsigned char message[];
};

struct recv_list {
	struct recieved_file *file;
	struct recv_list *next;
};


struct recieved_file {
	unsigned char mip_addr;
	uint16_t file_length;
	uint16_t port;
	uint16_t last_ack;
	uint16_t read_total;
	unsigned char file[];
};


struct connected_unix {
	int fd;
	uint16_t port;
	struct connected_unix *next;
};

struct epoll_control {
  int epoll_fd;
  int listening_fd;
  int mip_fd;
  struct connected_unix *app_fds;
  struct epoll_event events[MAX_EVENTS];
};

struct fdInfo {
  char *family;
  int listen;
  int fd;
};

//Global variables

int debug = 0;
const unsigned char zero = 0;
struct send_list *f_list = NULL;
struct recv_list *r_list = NULL;
int timeout = 0;

/**
 * [creates a mip header of 32 bytes using bit shifting on the arguments given]
 * @param  padding    [padding]
 * @param  port       [port]
 * @param  seq_number [Sequence Number]
 * @return            [the created header]
 */
uint32_t create_mip_header(uint padding, uint port, uint seq_number) {
	uint32_t header = 0;
	header ^= (-padding ^ header) & (padding << ((PADDING)));
	header ^= (-port ^ header) & (port << ((PORT)));
	header |= seq_number;
	return header;
}



/**
 * sends the file in miptp sized packages to a miptp at the given adresses via our local mip-daemon 
 * @param epctrl [contains socket information]
 * @param file   [the file to be sent]
 */
void send_file(struct epoll_control *epctrl, struct file_tp2* file) {
	for (int i = file->win_low ; i < file->win_high; ++i) {
		int length = 1492;

		if (i == file->tot_pack - 1) {
			length = file->last_packet_length + file->padding;
			//printf("%d last %d padding\n", file->last_packet_length, file->padding);
		}

		unsigned char buf[length + 5];
		buf[0] = file->mip_addr;
		memcpy(buf + 1, file->packets[i], length + 4);
		ssize_t ret = send(epctrl->mip_fd, buf, length + 5, 0);
		if (debug) {
			printf("%d Sent %zd bytes to mip: %d port: %d seq_number: %d\n",length, ret, file->mip_addr, file->port, i);
		}

	}
}


/**
 * adds a send_file to the send file list
 * @param new_file [the file]
 */
void add_file(struct file_tp2* new_file) {
	if (f_list == NULL) {
		struct send_list* new = malloc(sizeof(struct send_list));;
		new->file = new_file;
		new->last_ack = time(NULL);
		new->next = NULL;
		f_list = new;
		return;
	}

	struct send_list *new_node = malloc(sizeof(struct send_list));
	new_node->file = new_file;
	new_node->last_ack = time(NULL);
	new_node->next = NULL;
	struct send_list *temp = f_list;

	while(1) {
		if (temp->next == NULL) {
			printf("helpa meg");
			temp->next = new_node;
			return;
		}
		temp = temp->next;
	}
	return;
}

/**
 * finds and return the file with the given adress and port
 * @param  mip_addr [mip_dst]
 * @param  port     [port]
 * @return          [returns the file or NULL if it didnt find the file]
 */
struct file_tp2* find_send_file(unsigned char mip_addr, uint16_t port) {
	if (f_list == NULL) {
		return NULL;
	}

	struct send_list* temp = f_list;

	while(temp != NULL) {
		if (temp->file->port == port && temp->file->mip_addr == mip_addr) {
			return temp->file;
		}

		temp = temp->next;
	}

	return NULL;
}


/**
 * Removes the file with given mip_addr and port from the send_file list,
 * Get called when we want to remove a file that timed out or finished sending
 * @param mip_addr [destination mip of file]
 * @param port     [destination port of file]
 */
void rem_send_file(unsigned char mip_addr, uint16_t port) {
	if (f_list == NULL)
	{
		return;
	}

	if (f_list->file->port == port && f_list->file->mip_addr == mip_addr) {
		//struct send_list* temp = f_list;
		f_list = f_list->next;
		//free(temp->file);
		//free(temp);
		return;
	}

	struct send_list* temp = f_list->next;
	struct send_list* prev = f_list;
	while(temp != NULL && prev != NULL) {
		if (temp->file->port == port && temp->file->mip_addr == mip_addr) {
			prev->next = temp->next;
			//free(temp->file);
			//free(temp);
			return;
		}
		prev = temp;
		temp = temp->next;
	}
	return;
}

/**
 * adds a recv_file to the recv file list
 * @param new_file [the file to be added]
 */
void add_recv_file(struct recieved_file* new_file) {
	if (r_list == NULL) {
		struct recv_list* new = malloc(sizeof(struct recv_list));;
		new->file = new_file;
		new->next = NULL;
		r_list = new;
		return;
	}

	struct recv_list *new_node = malloc(sizeof(struct recv_list));
	new_node->file = new_file;
	new_node->next = NULL;
	struct recv_list *temp = r_list;

	while(1) {
		if (temp->next == NULL)
		{
			printf("helpa meg");
			temp->next = new_node;
			return;
		}
		temp = temp->next;
	}
	return;
}



/**
 * Removes the file with given mip_addr and port from the recv_file list,
 * Get called when we want to remove a file that finished recieving
 * @param mip_addr [destination mip of file]
 * @param port     [destination port of file]
 */
void rem_recv_file(unsigned char mip_addr, uint16_t port) {
	if (r_list == NULL)
	{
		return;
	}

	if (r_list->file->port == port && r_list->file->mip_addr == mip_addr) {
		//struct recv_list* temp = r_list;
		r_list = r_list->next;
		//free(temp->file);
		//free(temp);
		return;
	}

	struct recv_list* temp = r_list->next;
	struct recv_list* prev = r_list;
	while(temp != NULL && prev != NULL) {
		if (temp->file->port == port && temp->file->mip_addr == mip_addr) {
			prev->next = temp->next;
			//free(temp->file);
			//free(temp);
			return;
		}
		prev = temp;
		temp = temp->next;
	}
	return;

}

/**
 * finds and returns the file with the given port and mip_addr
 * @param  mip_addr [mip_src ]
 * @param  port     [port]
 * @return          [the file or NULL if it didnt find the file]
 */
struct recieved_file* find_recv_file(unsigned char mip_addr, uint16_t port) {
	if (r_list == NULL) {
		return NULL;
	}

	struct recv_list* temp = r_list;

	while(temp != NULL) {
		if (temp->file->port == port && temp->file->mip_addr == mip_addr) {
			return temp->file;
		}

		temp = temp->next;
	}

	return NULL;
}


/**
 * add a client to the list of clients
 * int fds: the socket of the client
 */
void add_client_to_list(struct epoll_control *epctrl, int fds) {
	struct connected_unix *new = malloc(sizeof(struct connected_unix));
	new->fd = fds;
	new->port = 0;
	
	if (epctrl->app_fds == NULL) {
		epctrl->app_fds = new;
		return;
	}

	struct connected_unix *temp = epctrl->app_fds;

	while(1) {
		if (temp->next == NULL) {
			temp->next = new;
			return;
		}
		temp = temp->next;
	}

	return;
}


/**
 * finds a client and its stored information in the clientlist
 * @param  epctrl [contains the client list]
 * @param  sock   [the client which we want to find the information about]
 * @return        client or NULL if no client was found
 */
struct connected_unix* get_client_fd_from_list(struct epoll_control *epctrl, int sock) {
	struct connected_unix *temp = epctrl->app_fds;
	while (temp != NULL) {
		if (temp->fd == sock) {
			return temp;
		}

		temp = temp->next;
	}

	//should not happen.
	return NULL;
}

/**
 * returns a client with the given port
 * @param  epctrl [contains the client list]
 * @param  port   [the port_adress of the client we want to find]
 * @return        [client or NULL if no client found]
 */
struct connected_unix* get_files_info(struct epoll_control *epctrl, uint16_t port) {
	struct connected_unix *temp = epctrl->app_fds;
	while (temp != NULL) {
		if (temp->port == port) {
			return temp;
		}

		temp = temp->next;
	}

	return NULL;
}

/**
 * removes a client from the list
 * @param epctrl [description]
 * @param fds    [description]
 */
void remove_client_from_list(struct epoll_control *epctrl, int fds) {
	if (epctrl->app_fds == NULL)  {
		return;
	}

	if (epctrl->app_fds->fd  == fds) {
        struct connected_unix * temp = epctrl->app_fds;
        epctrl->app_fds = epctrl->app_fds->next;
        free(temp);
        return;
    }

    struct connected_unix * current = epctrl->app_fds->next;
    struct connected_unix * previous = epctrl->app_fds;
    while (current != NULL && previous != NULL) {
        if (current->fd == 0) {
            struct connected_unix * temp = current;
            previous->next = current->next;
            free(temp);
            return;
        }
        previous = current;
        current = current->next;
    }
    return;
}


/**
 * creates and returns an accept socket listening to the sockpath argument, exits the program if the socket fails to be created
 * @param  sockpath
 * returns the file descriptor of the newly created socket
 */
int setup_miptp_socket(char* sockpath) {
  int sock_un = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  struct sockaddr_un sockaddr;
  sockaddr.sun_family = AF_UNIX;
  strcpy(sockaddr.sun_path, sockpath);

  unlink(sockpath);
  if(bind(sock_un, (struct sockaddr *)&sockaddr, sizeof(sockaddr))) {
    perror("setup_unix_socket: bind()");
    exit(EXIT_FAILURE);
  }

  if (listen(sock_un, 100)) {
    perror("setup_unix_socket: listen()");
    exit(EXIT_FAILURE);
  }

  return sock_un;
}


/**
 * [attempts to set up a connect socket to the mip-daemon]
 * @param  sockpath
 * @return          [the newly created socket]
 */
int setup_mipd_socket(char* sockpath) {
  int sock = socket(AF_UNIX, SOCK_SEQPACKET, 0);
  if (sock == -1) {
    perror("main: socket()");
    exit(EXIT_FAILURE);
  }

  struct sockaddr_un sockaddr;
  sockaddr.sun_family = AF_UNIX;
  strncpy(sockaddr.sun_path, sockpath, sizeof(sockaddr));

  if (connect(sock, (struct sockaddr *)&sockaddr, sizeof(sockaddr)) == -1) {
    perror("main: connect()");
    exit(EXIT_FAILURE);
  }
  return sock;
}


/**
 * adds the sent in socket to the sent in epoll_fd,
 * @param  epctrl    [struct containing the epoll fd]
 * @param  fd        [the fd to be added]
 * @param  listening [checks if the socket is an accept socket or not (1 = true, 0 = false)]
 * @param  family    [the socket family e.g (eth, client, forw, route)]
 */
void epoll_add(struct epoll_control *epctrl, int fd, int listening, char *family)
{
  //NB: HVis du bruker EPOLLET -> så må socket være NONBLOCKING
  if (debug) {
    printf("ADDED AN %s SOCKET WITH SD: %d \n",family, fd );
  }
  struct fdInfo *info = malloc(sizeof(struct fdInfo) + strlen(family) + 1);
  struct epoll_event ev;
  ev.events = EPOLLIN;
  info->listen = listening;
  info->family = family;
  info->fd = fd;
  ev.data.ptr = info;
  if (epoll_ctl(epctrl->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    perror("epoll_add: epoll_ctl()");
    exit(EXIT_FAILURE);
  }
  return;
}

/**
 * reads a file from client, fragments it into miptp sized packages, and then tries
 * to send those packages to another miptp-daemon via its mip-daemon.
 * It also recieves port number from a file_server and updates the information about the server.
 * @param epctrl [struct containing all the socket information]
 * @param info   [the event that triggered epoll]
 */
void handle_client_socket(struct epoll_control *epctrl, struct fdInfo *info) {
	unsigned char buf[66000];
	ssize_t rb = recv(info->fd, buf, sizeof(buf), 0);

	if (rb == 0) {
		printf("Client disconnected\n");
		close(info->fd);
		remove_client_from_list(epctrl, info->fd);
		return;
	}

	//A client wants to give us the port it listens to
	if (buf[0] == 255) {
		struct connected_unix *temp = get_client_fd_from_list(epctrl, info->fd);

		if (temp == NULL) {
			printf("connected unix is somehow NULL\n");
			return;
		}

		memcpy(&temp->port, buf + 1, sizeof(uint16_t));

		if (debug) {
			printf("CLIENT PORT %d SOCK %d \n",temp->fd, temp->port);
		}

		return;
	}


	uint16_t port;
	unsigned mip_addr = buf[0];
	memcpy(&port, buf + 1, 2);

	//If we already are sending to that destination then we discard that package, as i have used the mip_addr and port as a unuiqe indentifier for files
	//the downside of this is that a if we can only send one file at the time to the same file_server from one miptp.
	struct file_tp2 *tmp = find_send_file(mip_addr, port);
	if (tmp != NULL) {
		printf("PORT CURRENTLY OCCUPIED\n");
		return;
	}

	//A client sent us a file to transfer!
	uint16_t file_length;
	memcpy(&file_length, buf + 3, 2);
	uint16_t tot_pack = (file_length + (PAYLOAD_LENGTH - 1))/ PAYLOAD_LENGTH;
	struct file_tp2 *file = malloc(sizeof(struct file_tp2) + sizeof(struct miptp_packet*) * tot_pack);

	file->mip_addr = buf[0];
	memcpy(&file->port, buf + 1, 2);
	memcpy(&file->file_length, buf + 3, 2);
	file->win_low = 0;
	file->win_high = new_min(tot_pack, 10);
	file->tot_pack = tot_pack;
	file->recv_ack = 0;
	uint read = 0;
	unsigned char padding = 0;
	if (file_length - read < PAYLOAD_LENGTH) {

			if (file_length % 4 != 0){
				padding = 4 - ((file_length % PAYLOAD_LENGTH) % 4);
			}

			file->packets[0] = malloc(4 + file_length + padding);
			file->packets[0]->header = create_mip_header(padding, file->port, 0);
			memcpy(file->packets[0]->message, &file_length, sizeof(file_length));
			memcpy(file->packets[0]->message + 2, buf + 5 , file_length);
			file->last_packet_length = file_length - read;
			file->padding = padding;
 			//memset(file->packets[0]->message + file_length + 2, 0, padding);
		}

	else {
			file->packets[0] = malloc(4 + PAYLOAD_LENGTH);
			file->packets[0]->header = create_mip_header(padding, file->port, 0);
			memcpy(file->packets[0]->message, &file_length, sizeof(file_length));
			memcpy(file->packets[0]->message + 2, buf + 5 , PAYLOAD_LENGTH - 2);
			read += PAYLOAD_LENGTH - 2;
	}


	for (int i = 1; i < file->tot_pack; ++i) {
		padding = 0;
		if (file_length - read < PAYLOAD_LENGTH) {


			if ((file_length - read) % 4 != 0) {
				padding = 4 - ((file_length - read) % 4);
			}

			//printf("%d rest + padddding %d ", file_length - read, padding);


			file->packets[i] = malloc(4 + file_length - read + padding);
			file->packets[i]->header = create_mip_header(padding, file->port, i);
			memcpy(file->packets[i]->message, buf + read + 7, file_length - read);
			//memcpy(file->packets[i]->message + file_length - read, &zero, padding);
			file->last_packet_length = file_length - read;
			file->padding = padding;

			read = read + file_length - read;

		}

		else {
			file->packets[i] = malloc(4 + PAYLOAD_LENGTH);
			file->packets[i]->header = create_mip_header(0, file->port, i);
			memcpy(file->packets[i]->message, buf + read + 7, PAYLOAD_LENGTH);
			read += PAYLOAD_LENGTH;
		}

	}

	add_file(file);
	send_file(epctrl, file);

	if (debug) {
		printf("FILE: %u mip_addr %d port %d length %d tot_pack, read from client: %d\n", file->mip_addr, file->port, file->file_length, file->tot_pack, info->fd);
	}


	return;
}


/**
 * recieves either a ACK message of a miptp packet from our mip-daemon,
 * @param
 */
void handle_mip_socket(struct epoll_control *epctrl, struct fdInfo *info) {
	unsigned char buf[1500] = {'z'};

	ssize_t ret = recv(info->fd, buf, sizeof(buf), 0);

	if (ret == 0) {
		printf("daemon exited, exiting miptp\n");
		exit(0);
	}

	if (ret == -1) {
		perror("handle_mip_socket()");
		exit(EXIT_FAILURE);
	}

	if (debug) {
		printf("read %zd from daemon\n", ret);
	}
	unsigned char mip_addr = buf[0];
	uint32_t header;
	memcpy(&header, buf + 1, sizeof(uint32_t));
	unsigned char padding = header >> (PADDING);
	uint16_t port = (header >> (PORT)) & 16383;
	uint16_t seq_number = header & 65535;


	//printf("%d %d %d %d \n", mip_addr, padding, port, seq_number);

	//ack recieved
	if (ret == 5) {

		struct file_tp2 *file = find_send_file(mip_addr, port);

		if (file == NULL) {
			printf("No such file\n");
			return;
		}

		if (seq_number == file->win_low) {

			file->win_low = file->win_low + 1;
			file->win_high = new_min(file->win_low + 10, file->tot_pack);
			if (debug) {
				printf("ACK %d RECIEVED FROM %d %d\n", seq_number, mip_addr, port);
				printf("NEW WINDOW SIZE: <%d-%d>\n", file->win_low, file->win_high);
			}
			file->recv_ack = 1;
		}

		if (file->win_low == file->tot_pack) {
			printf("Finished sending file to %d %d\n", mip_addr, port);
			rem_send_file(mip_addr, port);
			return;
		}

		return;
	}

	//new file recieved with 1 packet
	if (seq_number == 0 && ret - 1 < 1496) {
		uint16_t file_length;
		memcpy(&file_length, buf + 5, 2);

		struct recieved_file *file = malloc(sizeof(struct recieved_file) + file_length);
		file->mip_addr = mip_addr;
		file->port = port;
		file->last_ack = 0;

		memcpy(file->file, buf + 7, ret - 7 - padding);

		file->read_total += ret - 7 - padding;

		unsigned char ack[5] = {0};
		ack[0] = mip_addr;
		uint32_t header = create_mip_header(0,port,0);
		memcpy(ack + 1,  &header, sizeof(header));
		ssize_t sb = send(epctrl->mip_fd, ack, 5, 0);

		if (sb == -1) {
			perror("failed to send ack");
			return;
		}

		struct connected_unix *client = get_files_info(epctrl, port);

		if (client == NULL) {
			printf("No connected client, file discarded\n");
			return;
		}

		ssize_t rb = send(client->fd, buf + 5, file_length + 2 , 0);

		printf("buf[6] %s\n", buf + 7);

		if (rb == -1) {
			perror("send file to client:");
			return;
		}
		printf("FILE %d %d FULLY RECIEVED\n", mip_addr, port);

		if (debug) {
			printf("sent %zd to client on port %d\n", rb, port);
		}
	}


	else if (seq_number == 0) {
		struct recieved_file *recv = find_recv_file(mip_addr, port);

		//recv file was already there
		if (recv != NULL) {

		printf("RESENT ACK 0 TO %d %d \n",mip_addr, port);
		unsigned char ack[5] = {0};
		ack[0] = mip_addr;
		uint32_t header = create_mip_header(0,port,0);
		memcpy(ack + 1,  &header, sizeof(header));
		ssize_t sb = send(epctrl->mip_fd, ack, 5, 0);

		if (sb == -1) {
			perror("failed to send ack");
			return;
		}

		return;
		}


		uint16_t file_length;
		memcpy(&file_length, buf + 5, 2);
		struct recieved_file *file = malloc(sizeof(struct recieved_file) + file_length);
		file->mip_addr = mip_addr;
		file->file_length = file_length;
		file->port = port;
		file->last_ack = 0;
		file->read_total = 0;
		memcpy(file->file, buf + 7, ret - 7 - padding);
		file->read_total += ret - 7 - padding;
		add_recv_file(file);

		if (debug){
			printf("FILE %d %d, RECIEVED PACKAGE %d, READ_TOTAL %d OF FILE_LENGTH %d\n", file->mip_addr, file->port, seq_number, file->read_total, file->file_length);
		}

		unsigned char ack[5] = {0};
		ack[0] = mip_addr;
		uint32_t header = create_mip_header(0,port,0);
		memcpy(ack + 1,  &header, sizeof(header));
		ssize_t sb = send(epctrl->mip_fd, ack, 5, 0);

		if (sb == -1) {
			perror("failed to send ack");
			free(file);
			return;
		}

	}


	else {

		struct recieved_file *recv = find_recv_file(mip_addr, port);

		if (recv == NULL) {
			printf("RECIEVED A INVALID PACKAGE \n");
			return;
		}

		if (recv->last_ack + 1 != seq_number) {
			printf("PACKAGE ARRIVED IN WRONG ORDER, PACKAGE DISCARDED %d\n", seq_number);
			return;
		}

		memcpy(recv->file + recv->read_total, buf + 5, ret - 5 - padding);
		recv->read_total += ret - 5 - padding;

		unsigned char ack[5] = {0};
		ack[0] = mip_addr;
		uint32_t header = create_mip_header(0,port,seq_number);
		memcpy(ack + 1,  &header, sizeof(header));
		ssize_t sb = send(epctrl->mip_fd, ack, 5, 0);

		if (sb == -1) {
			perror("failed to send ack");
			return;
		}

		recv->last_ack = recv->last_ack + 1;

		if (debug){
			printf("FILE %d %d, RECIEVED PACKAGE %d, READ_TOTAL %d OF FILE_LENGTH %d\n", recv->mip_addr, recv->port, seq_number, recv->read_total, recv->file_length);
		}


		if (recv->read_total == recv->file_length)	{
			printf("FILE %d %d FULLY RECIEVED\n", recv->mip_addr, recv->port);

			struct connected_unix *client = get_files_info(epctrl, port);

			if (client == NULL) {
				printf("No connected client, file discarded\n");
				rem_recv_file(mip_addr, port);
				return;
			}

			unsigned char send_buf[66000] = {0};
			memcpy(send_buf, &recv->file_length, 2);
			memcpy(send_buf + 2, recv->file, recv->file_length);

			//printf("%s\n",send_buf + 2 );

			ssize_t rb = send(client->fd, send_buf, recv->file_length + 2,0);

			if (rb == -1) {
				perror("send file to client:");
				rem_recv_file(mip_addr, port);
				return;
			}

			if (debug) {
				printf("sent %zd to client on port %d\n", rb, recv->port);
			}

			rem_recv_file(mip_addr, port);

			}

	}
}

/**
 * Adds the newly connected client to the client list.
 * @param epctrl [description]
 * @param info   [description]
 */
void handle_listening_socket(struct epoll_control *epctrl, struct fdInfo *info) {
	//a new client connected !
	    int connect_sock = 0;
	    struct sockaddr_un sockaddr = {0};
	    sockaddr.sun_family = AF_UNIX;
	    socklen_t addrlen = sizeof(sockaddr);
	    connect_sock = accept(epctrl->listening_fd, (struct sockaddr *)&sockaddr, &addrlen);

    if (connect_sock == -1) {
    	perror("epoll_event: accept()");
    	exit(EXIT_FAILURE);
    }

    add_client_to_list(epctrl, connect_sock);
    epoll_add(epctrl, connect_sock, 0, "client");
    if (debug) {
     	fprintf(stdout, "NEW CLIENT CONNECTION ESTABLISHED\n");
    }
}




/**
 * sends the event further down, to another method which parses and handles the event.
 * @param  epctrl [an struct which contains information about the sockets, and the epoll fd)]
 * @param  n      [index of which event we are handling know]
 */
void epoll_event(struct epoll_control *epctrl, int n) {
  struct fdInfo *info = epctrl->events[n].data.ptr;
  if (strcmp(info->family, "client") == 0 ) {
    handle_client_socket(epctrl, info);
  }

  else if (strcmp(info->family, "listening") == 0) {
    handle_listening_socket(epctrl, info);
  }

  else if (strcmp(info->family, "mip_daemon") == 0) {
    handle_mip_socket(epctrl, info);
  }

  else {
    printf("Unexpected socket behaviour! This should never happen!\n");
  }
}


/**
 * sets up the unix sockets and the epoll, then enters a loop waiting for clients to connect
 * @param  argc [number of args]
 * @param  args [the argument provided]
*/
int main(int argc, char* args[]) {

	if (argc < 4) {
		printf("Expected atleast 3 arguments\nGiven %d arguments\n", argc);
		printf("Usage: %s [-d] <MIPD_PATH> <MIPTP_PATH> <TIME_OUT>\n", args[0] );
		exit(-1);
	}

	struct epoll_control epctrl;
	epctrl.epoll_fd = epoll_create(99);
	epctrl.listening_fd = 0;
	epctrl.mip_fd = 0;
	epctrl.app_fds = NULL;

	if (epctrl.epoll_fd == - 1) {
		perror("main: epoll_create()");
		exit(EXIT_FAILURE);
	}

	if (strcmp(args[1], "-d") == timeout ) {

		if (argc < 5) {
		printf("TO FEW ARGUMENTS GIVEN WITH DEBUG MODE, EXPECTED 5 GIVEN %d\n", argc);
		printf("Usage: %s [-d] <MIPD_PATH> <MIPTP_PATH> <TIME_OUT>\n", args[0] );
		exit(-1);
	}

		printf("DEBUG MODE ENABLED\n");
		debug = 1;
		epctrl.mip_fd = setup_mipd_socket(args[2]);
		epctrl.listening_fd = setup_miptp_socket(args[3]);
		timeout = atoi(args[4]);
	}

	else {
		epctrl.mip_fd = setup_mipd_socket(args[1]);
		epctrl.listening_fd = setup_miptp_socket(args[2]);
		timeout = atoi(args[3]);
	}
	

	epoll_add(&epctrl, epctrl.mip_fd, 1, "mip_daemon");
	epoll_add(&epctrl, epctrl.listening_fd, 1, "listening");


	for(;;) {
		int nfds, n;
		nfds = epoll_wait(epctrl.epoll_fd, epctrl.events, MAX_EVENTS, 0);

		if (nfds == -1) {
			perror("main: epoll_wait");
			exit(EXIT_FAILURE);
		}

		for (n = 0; n < nfds; ++n)	{
			epoll_event(&epctrl, n);
		}

		struct send_list *curr = f_list;

		while(curr != NULL) {
			if (time(NULL) - curr->last_ack > timeout) {
				send_file(&epctrl, curr->file);
				//this is a really cumbersome way but, i did not manage to store the time_t in the file_tp2 struct
				if (curr->file->recv_ack == 1) {
					curr->last_ack = time(NULL);
				}
			}

			//if we fail to get an ACK in 5 attempts, then we can assume that something has gone wrong
			if (time(NULL) - curr->last_ack > timeout * 5) {
				printf("failed to recieve ACK from %d %d 5 times, Discardig file\n", curr->file->mip_addr, curr->file->port);
				rem_send_file(curr->file->mip_addr, curr->file->port);
			}
			curr = curr->next;
		}
	}

	return 1;
}
