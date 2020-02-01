#include "header.h"
#include "colours.h"
#include <time.h>

#define TTL 15
#define BUF_SIZE 1500
#define POISON TTL + 1
#define TIME_OUT 30 //Time until a route is INVALIDATED
#define FLUSH 60   //time until a route is REMOVED,
#define PRINT_DELAY 20
#define UNICAST_DELAY 10 //how often we should unicast
#define FOREVER for(;;)
#define MAX_EVENTS 20

struct routing_info {
  unsigned char mip;
  unsigned char cost;
  unsigned char next_jump;
  time_t last_updated;
};

struct local_mip {
  unsigned char mip;
  struct local_mip *next;
};


typedef struct epoll_control {
  int epoll_fd;
  int rout_fd;
  int forw_fd;
  struct epoll_event events[MAX_EVENTS];
} epoll_control;

//GLOBAL VARIABLES
struct routing_info* routing_table[255] = {NULL};
struct local_mip *local_list = NULL;
unsigned char broadcast = 255;
unsigned char updated = 0;
time_t lastbroadcast;			// Last time broadcast was sent
time_t lastunicast;				// Last time update was sent
time_t last_print = 0;
int debug = 0;

/**
 *    adds a route to a linked list, marking the route as a local rotue.
 *   * @param local_new [local route to be added]
 */
void add_local (struct local_mip *local_new) {
  if (local_list == NULL) {
    local_list = local_new;
    return;
  }
  struct local_mip *local_temp = local_list->next;
  while (local_temp != NULL) {
    if (local_temp->next == NULL) {
      local_temp->next = local_new;
      return;
    }
    local_temp = local_temp->next;
  }
  local_list->next = local_new;
}


/**
 * prints the routing table
 */
void print_routing_table() {
  printf("\n~~~~~~~~ROUTE TABLE~~~~~~~~\n");
  for (size_t i = 0; i < 255; i++) {
    if (routing_table[i] != NULL) {
      printf("Adress: %d Cost: %d Via: %d \n", routing_table[i]->mip, routing_table[i]->cost, routing_table[i]->next_jump);
    }
  }
  last_print = time(NULL);
}


/**
 * compare two route to check if they are indentical, (i.e same dest, cost and next_jump)
 * @param  route1 [route 1]
 * @param  route2 [route2]
 * @return 1 if they are the same, and zero if they are different
 */
int compare_routes(struct routing_info *route1, struct routing_info *route2) {
  if (route1 == NULL || route2 == NULL) {
    printf("dette burde ikke skje\n");
    return 0;
  }

  if (route1->mip == route2->mip && route1->cost == route2->cost && route1->next_jump == route2->next_jump) {
    return 1;
  }
  return 0;
}


/**
 * iterates throught the routing_table to see if it can INVALIDATE or REMOVE some of the routes,
 */
void rinse_routing_table() {
  for (size_t i = 0; i < 255; i++) {
    if (routing_table[i] == NULL) {
      continue;
    }

    else if (routing_table[i]->cost == 0) {
      continue;
    }

    else if (time(NULL) - routing_table[i]->last_updated > TIME_OUT && routing_table[i]->cost != POISON) {
      printf("INVALIDATED ROUTE TO %d\n",routing_table[i]->mip);
      routing_table[i]->cost = POISON;
      continue;
    }

    else if (time(NULL) - routing_table[i]->last_updated > FLUSH) {
      printf("REMOVED ROUTE TO %d \n",routing_table[i]->mip);
      free(routing_table[i]);
      routing_table[i] = NULL;
      continue;
    }
  }
}


/**
 * Broadcasts all local routes to the Daemon, which will then send the information to its neighbours
 */
void broadcast_routes(epoll_control *epctrl) {
  struct local_mip *local_current = local_list;
  unsigned char buf[BUF_SIZE] = {0};
  buf[0] = 255;
  int i = 1;
  //struct routing_info info_current = NULL;

  while (local_current != NULL) {
    buf[i] = local_current->mip;
    i++;
    buf[i] = 0;
    i++;
    buf[i] = local_current->mip;
    i++;
    local_current = local_current->next;
  }

  ssize_t ret = send(epctrl->rout_fd,buf, i,0);

  if (ret == -1 ) {
    perror("broadcast_routes(): ");
    exit(EXIT_FAILURE);
  }

  if (ret == 0 ) {
    printf("Daemon disconected! no reason for me to go on!\n");
    exit(EXIT_FAILURE);
  }

  else {
    printf("Broadcasted local_mips!\n");
    lastbroadcast = time(NULL);
    return;
  }
}


/**
 * adresses a packet to each neighbour (cost == 1), with information about our routes that does not go through that specific neighbour,
 * It then sends the packet to the daemon, and lets the daemon handle eventuall arp_requst/sending of package to the adressed router
 * @param epctrl [Struct containing the necessary fds]
 */
void unicast_routes(epoll_control *epctrl) {
  //we can assume that routes with cost of 1 is a neighbour
  //and to avoid "counting to infinity" we dont send the routes to a neighbour if we route to or via that neighbour
  for (size_t i = 0; i < 255; i++) {

    if (routing_table[i] != NULL) {
      struct routing_info *neighbour = routing_table[i];

      if (neighbour->cost != 1) {
        continue;
      }

      if (neighbour->mip != neighbour->next_jump) {
        continue;
      }

      unsigned char buf[BUF_SIZE] = {0};
      buf[0] = neighbour->mip;
      // printf("to be sent, %d\n", buf[0]);
      int x = 1;

      for (size_t j = 0; j < 255; j++) {

        struct routing_info *current = routing_table[j];
        if (current == NULL) {
          continue;
        }

        else if (current->mip == neighbour->mip || current->next_jump == neighbour->mip) {
          continue;
        }

        else {
          buf[x] = current->mip;
          x++;
          buf[x] = current->cost;
          x++;
          buf[x] = current->next_jump;
          x++;
        }
      }

      ssize_t ret = send(epctrl->rout_fd, buf, x,0);
      usleep(500);
      if (ret == -1) {
        perror("unicast_routes(): ");
        exit(EXIT_FAILURE);
      }

      if (ret == 0) {
        printf("daemon disconected, no reason to me to go on anymore :((\n" );
        exit(EXIT_FAILURE);
      }

      printf("sent unicast to %d of %zd bytes \n",buf[0], ret );
      }
  }
  lastunicast = time(NULL);
  updated = 0;
}


/**
 * answer the daemons next_jump request, sends the response as a 1 byte message containng the next jump, sends 255 if no valid jump was found
 * @param epctrl [Struct containg the necessary fds]
 */
void route_look_up(epoll_control *epctrl) {
  unsigned char mip_addr = 0;
  ssize_t ret = recv(epctrl->forw_fd, &mip_addr, sizeof(mip_addr),0);

  if (ret == -1) {
    perror("route_look_up() : ");
    exit(EXIT_FAILURE);
  }

  if (ret == 0) {
    printf("daemon disconected, no reason to me to go on anymore :((\n" );
    exit(EXIT_FAILURE);
  }

  printf("HERE WE ARE %d \n", mip_addr);
  if (mip_addr >= 255) {
    send(epctrl->forw_fd,&broadcast,sizeof(mip_addr),0);
    return;
  }
  else if (routing_table[mip_addr] == NULL) {
    send(epctrl->forw_fd,&broadcast,sizeof(mip_addr),0);
  }
  else {
    send(epctrl->forw_fd,&(routing_table[mip_addr]->next_jump),sizeof(unsigned char),0);
    printf("BABBAOOOOLK %d\n", routing_table[mip_addr]->next_jump);
  }
  return;
}


/**
 * Handles the routing information recieved from another routing_server in the network, it reads the information, then check if it is a poisoned message,
 * then checks if it is better than our current route to the given mip.
 * @param epctrl [Struct containing the necessary fds]
 */
void handle_routing(epoll_control *epctrl) {
  /*
    Recieves info about routes from daemon.
    Info is in this format:
    [FROM] <DST1> <COST1> <VIA1> ... <DSTN> <COSTN> <VIAN>
    if from is 255, then it is the router sending its local mips.
    else it is a routing_package from another router.
    */

  unsigned char buf[BUF_SIZE] = {0}; //the upper of limit that can be sent through ehternet
  ssize_t ret = recv(epctrl->rout_fd,buf,sizeof(buf),0);
  if (ret == -1) {
    perror("handle_routing() :");
    exit(EXIT_FAILURE);
  }

  if (ret == 0) {
    printf("daemon disconected, no reason to me to go on anymore :((\n" );
    exit(EXIT_FAILURE);
  }
  if (debug) {
    printf("read %zd bytes from daemon\n", ret);
  }

  if ((ret - 1) % 3 != 0) {
    printf("Routing package unnexpected format, package dropped\n");
    return;
  }

  unsigned char from = 0;
  from = buf[0];
  int i = 1;

  //local mips from daemon, sent from daemon when we connected to it.
  if (from == 255) {
    printf("FROM %d\n", from);
    for (; i < ret;) {
      struct routing_info *info = malloc(sizeof(struct routing_info));
      info->mip = buf[i];
      i++;
      info->cost = buf[i];
      i++;
      info->next_jump = buf[i];
      i++;
      info->last_updated = time(NULL);
      struct local_mip *temp = malloc(sizeof(struct local_mip));
      temp->mip = info->mip;
      temp->next = NULL;
      add_local(temp);
      //printf("A: %d C: %d V: %d  I: %d\n",info->mip, info->cost, info->next_jump, i);
      routing_table[info->mip] = info;
    }

    broadcast_routes(epctrl);
  }

  //information about routes from another routhing_server.
  else {

    for (; i < ret;) {
      struct routing_info *info = malloc(sizeof(struct routing_info));
      info->mip = buf[i];
      i++;
      info->cost = buf[i] + 1;
      i++;
      info->next_jump = from;
      i++;
      info->last_updated = time(NULL);

      //printf("A: %d C: %d V: %d  I: %d\n",info->mip, info->cost, info->next_jump, i);
      //I implemnted this to avoid a count to infinty (15) occuring between C-D-B if either A or E disconected.
      //since i didn't wanna wait for them to count to 15.
      //
      if (info->cost - 1 == POISON) {
        printf("That line poison yo! \n");
        if (routing_table[info->mip] != NULL) {
          free(routing_table[info->mip]);
          routing_table[info->mip] = NULL;
        }

        free(info);
        continue;
      }

      //unreacheable due to TTL
      if (info->cost == 16) {
        printf("%d BIP BOP IM AN\n", info->cost );
        free(info);
        continue;
      }


      if (routing_table[info->mip] == NULL) {
        routing_table[info->mip] = info;
        updated = 1;
        continue;
      }

      else if (routing_table[info->mip]->cost > info->cost) {
        free(routing_table[info->mip]);
        routing_table[info->mip] = info;
        updated = 1;
        continue;
      }

      else if (compare_routes(routing_table[info->mip], info) == 1) {
        routing_table[info->mip]->last_updated = time(NULL);
        free(info);
        continue;
      }

      else {
        free(info);
        continue;
      }
    }

    if (updated) {
      unicast_routes(epctrl);
      updated = 0;
      print_routing_table();
      last_print = time(NULL);
    }
  }
}

/**
 * adds a socket to the epoll_fd
 * @param  epctrl [a struct containing the necessary information]
 * @param  fd     [socket to be added]
 */
void epoll_add(epoll_control *epctrl, int fd)
{
  //NB: HVis du bruker EPOLLET -> så må socket være NONBLOCKING
  struct epoll_event ev;
  ev.events = EPOLLIN;
  ev.data.fd = fd;
  if (epoll_ctl(epctrl->epoll_fd, EPOLL_CTL_ADD, fd, &ev) == -1) {
    perror("epoll_add: epoll_ctl()");
    exit(EXIT_FAILURE);
  }
}


/**
 * Checks which socket we recieved information from, then send the information further up to the socket handler
 * @param  epctrl [a struct containing the necessary information and the event we are looking at]
 * @param  n     which event we are to look at
 *  */
int epoll_event(epoll_control *epctrl, int n)
{

  //daemon wants jump!
  if (epctrl->events[n].data.fd == epctrl->forw_fd) {
    route_look_up(epctrl);
    return 1;
  }

  //routing information received
  else if (epctrl->events[n].data.fd == epctrl->rout_fd) {
    handle_routing(epctrl);
    return 1;
  }

  else {printf("noko gik kgali ");}
  return 1;
}


/**
 * [attempts to set up a socket on the given sockpath]
 * @param  sockpath
 * @return          [the newly created socket]
 */
int setup_unix_socket(char* sockpath) {
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
 * [sets up the two required unix sockets then enters the loop, waiting for EPOLLIN from daemon]
 * @param  argc [number of arguments]
 * @param  argv [an array containing the arguments]
 */
int main(int argc, char* argv[]) {
  printf("%d\n", POISON);
  if (argc < 3) {
    printf(RED "Wrong Usage of program\n" RESET);
    printf(RED "Usage: %s [-h] <Socket_router> <Socket_forwarding>\n" RESET, argv[0]);
    exit(EXIT_FAILURE);
  }
  epoll_control epctrl;
  epctrl.epoll_fd = epoll_create(99);

  if(epctrl.epoll_fd == -1) {
    perror("main: epoll_create()");
    exit(EXIT_FAILURE);
  }

  epctrl.rout_fd = setup_unix_socket(argv[1]);
  epctrl.forw_fd = setup_unix_socket(argv[2]);

  epoll_add(&epctrl, epctrl.rout_fd);
  epoll_add(&epctrl, epctrl.forw_fd);

  FOREVER {
    int nfds, n;
    nfds = epoll_wait(epctrl.epoll_fd, epctrl.events, MAX_EVENTS, 10000);
    if (nfds == -1) {
      perror("main: epoll_wait");
      exit(EXIT_FAILURE);
    }
    for (n = 0; n < nfds; n++) {
      epoll_event(&epctrl, n);
    }

    if (time(NULL) - last_print > PRINT_DELAY) {
      print_routing_table();
    }

    if (time(NULL) - lastunicast > UNICAST_DELAY) {
      unicast_routes(&epctrl);
    }

    rinse_routing_table();
  }
  return 0;

}
