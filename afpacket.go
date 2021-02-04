// +build linux

package main

// #cgo CFLAGS: -g -Wall
//#include <string.h>
//#include <stdio.h>
//#include <stdlib.h>
//#include <sys/socket.h>
//#include <linux/if_packet.h>
//#include <net/if_arp.h>
//#include <sys/time.h>
//#include <sys/types.h>
//#include <net/ethernet.h>
//#include <arpa/inet.h>
//#include <net/if.h>
//#include <sys/ioctl.h>
//#include <errno.h>
//#include <linux/ip.h>
//#include <netinet/udp.h>
//#include <netinet/tcp.h>
//#include <getopt.h>
//#include <stdbool.h>
//#include <ifaddrs.h>
//#include <ctype.h>
//#include <unistd.h>
//#include <poll.h>
//#include <signal.h>
//#include <sys/mman.h>
//#include <linux/ip.h>
//#include <linux/net_tstamp.h>
//#include <assert.h>
//#include <netdb.h>
//#include <sys/wait.h>
//#include <pthread.h>
//#include <sys/syscall.h>
//# define PACKET_FANOUT			18
//# define PACKET_FANOUT_HASH		0
//# define PACKET_FANOUT_LB		1
//
//#ifndef likely
//# define likely(x)		__builtin_expect(!!(x), 1)
//#endif
//#ifndef unlikely
//# define unlikely(x)		__builtin_expect(!!(x), 0)
//#endif
//
//#define UNUSED(x) (void)(x)
//
// struct block_desc {
//     uint32_t version;
//     uint32_t offset_to_priv;
//     struct tpacket_hdr_v1 h1;
// };
//
// struct ring {
//     struct iovec *rd;
//     uint8_t *map;
//     struct tpacket_req3 req;
// };
//
// struct flgags {
//     bool set_promiscuous_flag;
//     bool device_list_flag;
//     bool multi_threading_flag;
// };
//
// struct thread_args {
//     char* interface_name;
//     bool set_promiscuous_flag;
//     int fanout_id;
// };
//
// const int ALL  =  0x0003;
// const int IP   =  0x0800;
// const int ARP  =  0x0806;
//
// static unsigned long total_packets = 0;
// static unsigned long total_bytes = 0;
//
// pthread_mutex_t lock;
//
// static sig_atomic_t sigint = 0;
//
// const int PACKET_LENGTH = 65535;
//
// unsigned int blocksize = 1 << 22;
// unsigned int framesize = 1 << 11;
// unsigned int block_number = 64;
//
// static void signal_handler()
// {
//     sigint = 1;
// }
//
// void set_packet_version(int socket_descriptor){
//     int packet_version = TPACKET_V3;
//     if (setsockopt(socket_descriptor, SOL_PACKET, PACKET_VERSION, &packet_version, sizeof(packet_version)) < 0){
//         printf("Error: %s\n",strerror(errno));
//         printf("Can't set packet v3 version\n");
//         exit(1);
//     }
// }
//
// void get_all_device_list(){
//     struct if_nameindex *if_nidxs, *intf;
//     if_nidxs = if_nameindex();
//     if ( if_nidxs != NULL ){
//         for (intf = if_nidxs; intf->if_index != 0 || intf->if_name != NULL; intf++){
//             printf("%s\n", intf->if_name);
//         }
//         if_freenameindex(if_nidxs);
//     }
// }
//
// void get_af_packet_family_device_list(){
//     struct ifaddrs *addrs,*tmp;
//     getifaddrs(&addrs);
//     tmp = addrs;
//     while (tmp)
//     {
//         if(tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET){
//             printf("%s\n", tmp->ifa_name);}
//         tmp = tmp->ifa_next;
//     }
//     freeifaddrs(addrs);
// }
//
// int create_socket(int protocol){
//     // create PF_PACKET socket
//     if (protocol == ALL || protocol == IP || protocol == ARP){
//         int libpackiffersocket = socket(AF_PACKET, SOCK_RAW, htons(protocol));
//         if (libpackiffersocket < 0){
//             printf("Error: %s\n",strerror(errno)); exit(1);
//         }
//         return libpackiffersocket;
//     }
//     else {printf("Error: unsupported protocol!"); exit(1);}
// }
//
// int get_interface_index(int socket_descriptor, const char * interface){
//     // get interface index
//     struct ifreq sifr;
//     memset(&sifr, 0, sizeof(sifr));
//     strncpy(sifr.ifr_name, interface, sizeof(sifr.ifr_name));
//     if (ioctl(socket_descriptor, SIOCGIFINDEX, &sifr) == -1){
//         printf("Error: %s",strerror(errno));exit(1);
//     }
//     return sifr.ifr_ifindex;
// }
//
// struct sockaddr_ll fill_link_layer(int interface_index, int protocol){
//     // fill link layer hedaer
//     struct sockaddr_ll psll;
//     memset(&psll, 0, sizeof(psll));
//     psll.sll_family = PF_PACKET;
//     psll.sll_ifindex = interface_index;
//     psll.sll_protocol = htons(protocol);
//     return psll;
// }
//
// void bind_socket(int socket_descriptor, struct sockaddr_ll psll){
//     if (bind(socket_descriptor, (struct sockaddr *)&psll, sizeof(psll)) == -1){
//         printf("Error: %s",strerror(errno));exit(1);
//     }
// }
//
// void set_promiscuous(int socket_descriptor, int interface_index){
//     struct packet_mreq pmreq;
//     memset(&pmreq, 0, sizeof(struct packet_mreq));
//     pmreq.mr_type = PACKET_MR_PROMISC;
//     pmreq.mr_ifindex = interface_index;
//     if(setsockopt (socket_descriptor, SOL_SOCKET, PACKET_ADD_MEMBERSHIP, &pmreq, sizeof(struct packet_mreq)) < 0){
//         printf("Error: %s",strerror(errno));exit(1);
//     }
// }
//
// void set_packet_rx_ring(int socket_descriptor, struct ring *ring){
//     memset(&ring->req, 0, sizeof(ring->req));
//     ring->req.tp_block_size = blocksize;
//     ring->req.tp_frame_size = framesize;
//     ring->req.tp_block_nr = block_number;
//     ring->req.tp_frame_nr = (blocksize * block_number) / framesize;
//     ring->req.tp_retire_blk_tov = 60;
//     ring->req.tp_feature_req_word = TP_FT_REQ_FILL_RXHASH;
//     if(setsockopt(socket_descriptor, SOL_PACKET, PACKET_RX_RING, &ring->req,sizeof(ring->req)) < 0) {
//         printf("Error: %s",strerror(errno));exit(1);
//         exit(1);
//     }
//
//     ring->map = mmap(NULL, ring->req.tp_block_size * ring->req.tp_block_nr,
//              PROT_READ | PROT_WRITE, MAP_SHARED | MAP_LOCKED, socket_descriptor, 0);
//     if(ring->map == MAP_FAILED) {
//         perror("mmap");
//         exit(1);
//     }
//
//     ring->rd = malloc(ring->req.tp_block_nr * sizeof(*ring->rd));
//     assert(ring->rd);
//     for(unsigned int i = 0; i < ring->req.tp_block_nr; ++i) {
//         ring->rd[i].iov_base = ring->map + (i * ring->req.tp_block_size);
//         ring->rd[i].iov_len = ring->req.tp_block_size;
//     }
// }
//
// static void display(struct tpacket3_hdr *ppd)
// {
//     struct ethhdr *eth = (struct ethhdr *) ((uint8_t *) ppd + ppd->tp_mac);
//     struct iphdr *ip = (struct iphdr *) ((uint8_t *) eth + ETH_HLEN);
//
//     if (eth->h_proto == htons(ETH_P_IP)) {
//         struct sockaddr_in ss, sd;
//         char sbuff[NI_MAXHOST], dbuff[NI_MAXHOST];
//
//         memset(&ss, 0, sizeof(ss));
//         ss.sin_family = PF_INET;
//         ss.sin_addr.s_addr = ip->saddr;
//         getnameinfo((struct sockaddr *) &ss, sizeof(ss),
//                 sbuff, sizeof(sbuff), NULL, 0, NI_NUMERICHOST);
//
//         memset(&sd, 0, sizeof(sd));
//         sd.sin_family = PF_INET;
//         sd.sin_addr.s_addr = ip->daddr;
//         getnameinfo((struct sockaddr *) &sd, sizeof(sd),
//                 dbuff, sizeof(dbuff), NULL, 0, NI_NUMERICHOST);
//
//         printf("%s -> %s, ", sbuff, dbuff);
//     }
//
//     printf("rxhash: 0x%x\n", ppd->hv1.tp_rxhash);
// }
//
// static void walk_block(struct block_desc *pbd)
// {
//     int num_pkts = pbd->h1.num_pkts, i;
//     unsigned long bytes = 0;
//     struct tpacket3_hdr *ppd;
//
//     ppd = (struct tpacket3_hdr *) ((uint8_t *) pbd +
//                        pbd->h1.offset_to_first_pkt);
//     for (i = 0; i < num_pkts; ++i) {
//         bytes += ppd->tp_snaplen;
//         display(ppd);
//
//         ppd = (struct tpacket3_hdr *) ((uint8_t *) ppd +
//                            ppd->tp_next_offset);
//     }
//     pthread_mutex_lock(&lock);
//     total_packets += num_pkts;
//     total_bytes += bytes;
//     pthread_mutex_unlock(&lock);
// }
//
// static void flush_block(struct block_desc *pbd)
// {
//     pbd->h1.block_status = TP_STATUS_KERNEL;
// }
//
// static void teardown_socket(struct ring *ring, int socket_descriptor)
// {
//     munmap(ring->map, ring->req.tp_block_size * ring->req.tp_block_nr);
//     free(ring->rd);
//     close(socket_descriptor);
// }
//
// void set_packet_fanout(int socket_descriptor, int fanout_id){
//      if (setsockopt(socket_descriptor, SOL_PACKET, PACKET_FANOUT, &fanout_id, sizeof(fanout_id)) < 0) {
//         perror("setsockopt");
//         exit(1);
//      }
// }
//
// void set_packet_timestamp(int socket_descriptor){
//     int req = SOF_TIMESTAMPING_RAW_HARDWARE;
//         if(setsockopt(socket_descriptor, SOL_PACKET, PACKET_TIMESTAMP, (void *) &req, sizeof(req)) < 0){
//            printf("Error: %s",strerror(errno));exit(1);
//         }
// }
//
// void process_ethernet(struct ethhdr **eth, bool dump){
//     if(dump == true) {
//         FILE * fp;
//         fp = fopen ("file.dat","a");fprintf(fp, "\nEthernet Header\n");
//         fprintf(fp, "\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",(*eth)->h_source[0],(*eth)->h_source[1],(*eth)->h_source[2],(*eth)->h_source[3],(*eth)->h_source[4],(*eth)->h_source[5]);
//         fprintf(fp, "\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",(*eth)->h_dest[0],(*eth)->h_dest[1],(*eth)->h_dest[2],(*eth)->h_dest[3],(*eth)->h_dest[4],(*eth)->h_dest[5]);
//         fprintf(fp, "\t|-Protocol : %d\n",ntohs((*eth)->h_proto)); fclose(fp);
//     }
//     else{
//         printf("\nEthernet Header\n");
//         printf("\t|-Source Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",(*eth)->h_source[0],(*eth)->h_source[1],(*eth)->h_source[2],(*eth)->h_source[3],(*eth)->h_source[4],(*eth)->h_source[5]);
//         printf("\t|-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X\n",(*eth)->h_dest[0],(*eth)->h_dest[1],(*eth)->h_dest[2],(*eth)->h_dest[3],(*eth)->h_dest[4],(*eth)->h_dest[5]);
//         printf("\t|-Protocol : %d\n",ntohs((*eth)->h_proto));
//     }
// }
//
// void process_arp(struct arpreq **arp, bool dump){
//     if(dump == true){}else{}UNUSED(arp);
// }
//
// void process_ip(struct iphdr **ip, bool dump){
//     struct sockaddr_in source, dest;
//     memset(&source, 0, sizeof(source));
//     source.sin_addr.s_addr = (*ip)->saddr;
//     memset(&dest, 0, sizeof(dest));
//     dest.sin_addr.s_addr = (*ip)->daddr;
//     if(dump == true){
//         FILE * fp;
//         fp = fopen ("file.dat","a");fprintf(fp, "\nIP Header\n");
//         fprintf(fp, "\t|-Version : %d\n", (unsigned int)(*ip)->version);
//         fprintf(fp, "\t|-Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)(*ip)->ihl,((unsigned int)((*ip)->ihl))*4);
//         fprintf(fp, "\t|-Type Of Service : %d\n", (unsigned int)(*ip)->tos);
//         fprintf(fp, "\t|-Total Length : %d Bytes\n", ntohs((*ip)->tot_len));
//         fprintf(fp, "\t|-Identification : %d\n", ntohs((*ip)->id));
//         fprintf(fp, "\t|-Time To Live : %d\n", (unsigned int)(*ip)->ttl);
//         fprintf(fp, "\t|-Protocol : %d\n", (unsigned int)(*ip)->protocol);
//         fprintf(fp, "\t|-Header Checksum : %d\n", ntohs((*ip)->check));
//         fprintf(fp, "\t|-Source IP : %s\n", inet_ntoa(source.sin_addr));
//         fprintf(fp, "\t|-Destination IP : %s\n", inet_ntoa(dest.sin_addr));fclose(fp);
//     }
//     else{
//         printf("\nIP Header\n");
//         printf("\t|-Version : %d\n", (unsigned int)(*ip)->version);
//         printf("\t|-Internet Header Length : %d DWORDS or %d Bytes\n",(unsigned int)(*ip)->ihl,((unsigned int)((*ip)->ihl))*4);
//         printf("\t|-Type Of Service : %d\n", (unsigned int)(*ip)->tos);
//         printf("\t|-Total Length : %d Bytes\n", ntohs((*ip)->tot_len));
//         printf("\t|-Identification : %d\n", ntohs((*ip)->id));
//         printf("\t|-Time To Live : %d\n", (unsigned int)(*ip)->ttl);
//         printf("\t|-Protocol : %d\n", (unsigned int)(*ip)->protocol);
//         printf("\t|-Header Checksum : %d\n", ntohs((*ip)->check));
//         printf("\t|-Source IP : %s\n", inet_ntoa(source.sin_addr));
//         printf("\t|-Destination IP : %s\n", inet_ntoa(dest.sin_addr));
//     }
// }
//
// void process_udp(struct udphdr **udp, bool dump){
//     if(dump == true){
//         FILE * fp;
//         fp = fopen ("file.dat","a");fprintf(fp, "\nUDP Header\n");
//         fprintf(fp, "\t|-Source Port : %d\n", ntohs((*udp)->source));
//         fprintf(fp, "\t|-Destination Port : %d\n", ntohs((*udp)->dest));
//         fprintf(fp, "\t|-Length : %d\n", ntohs((*udp)->len));
//         fprintf(fp, "\t|-Checksum : %d\n", ntohs((*udp)->check)); fclose(fp);
//     }
//     else{
//         printf("\nUDP Header\n");printf("\t|-Source Port : %d\n", ntohs((*udp)->source));
//         printf("\t|-Destination Port : %d\n", ntohs((*udp)->dest));
//         printf("\t|-Length : %d\n", ntohs((*udp)->len));
//         printf("\t|-Checksum : %d\n", ntohs((*udp)->check));
//     }
// }
//
// void process_tcp(struct tcphdr **tcp, bool dump){
//     if(dump == true){
//         FILE * fp;
//         fp = fopen ("file.dat","a");fprintf(fp, "\nTCP Header\n");
//         fprintf(fp, "\t|-Source Port : %d\n", ntohs((*tcp)->source));
//         fprintf(fp, "\t|-Destination Port : %d\n", ntohs((*tcp)->dest));
//         fprintf(fp, "\t|-Sequence Number : %d\n", ntohl((*tcp)->seq));
//         fprintf(fp, "\t|-Acknowledgement Number : %d\n", ntohl((*tcp)->ack_seq));
//         fprintf(fp, "\t|-Window : %d\n", ntohs((*tcp)->window));
//         fprintf(fp, "\t|-Checksum : %d\n", ntohs((*tcp)->check));
//         fprintf(fp, "\t|-Urgent Pointer : %d\n", ntohs((*tcp)->urg_ptr));
//         fprintf(fp, "\t\t|-Data Offset : %d\n", ntohs((*tcp)->doff));
//         fprintf(fp, "\t\t|-Reserved : %d\n", ntohs((*tcp)->res1));
//         fprintf(fp, "\t\t|-Reserved : %d\n", ntohs((*tcp)->res2));fprintf(fp, "\t\tFlags\n");
//         fprintf(fp, "\t\t|-No More Data From Sender : %d\n", ntohs((*tcp)->fin));
//         fprintf(fp, "\t\t|-Synchronize Sequence Numbers : %d\n", ntohs((*tcp)->syn));
//         fprintf(fp, "\t\t|-Reset The Connection : %d\n", ntohs((*tcp)->rst));
//         fprintf(fp, "\t\t|-Push Function : %d\n", ntohs((*tcp)->psh));
//         fprintf(fp, "\t\t|-Acknowledgment Field Significant : %d\n", ntohs((*tcp)->ack));
//         fprintf(fp, "\t\t|-Urgent Pointer Field Significant : %d\n", ntohs((*tcp)->urg));fclose(fp);
//     }
//     else{
//         printf("\nTCP Header\n");printf("\t|-Source Port : %d\n", ntohs((*tcp)->source));
//         printf("\t|-Destination Port : %d\n", ntohs((*tcp)->dest));
//         printf("\t|-Sequence Number : %d\n", ntohl((*tcp)->seq));
//         printf("\t|-Acknowledgement Number : %d\n", ntohl((*tcp)->ack_seq));
//         printf("\t|-Window : %d\n", ntohs((*tcp)->window));
//         printf("\t|-Checksum : %d\n", ntohs((*tcp)->check));
//         printf("\t|-Urgent Pointer : %d\n", ntohs((*tcp)->urg_ptr));
//         printf("\t\t|-Data Offset : %d\n", ntohs((*tcp)->doff));
//         printf("\t\t|-Reserved : %d\n", ntohs((*tcp)->res1));
//         printf("\t\t|-Reserved : %d\n", ntohs((*tcp)->res2));
//         printf("\t\tFlags\n");printf("\t\t|-No More Data From Sender : %d\n", ntohs((*tcp)->fin));
//         printf("\t\t|-Synchronize Sequence Numbers : %d\n", ntohs((*tcp)->syn));
//         printf("\t\t|-Reset The Connection : %d\n", ntohs((*tcp)->rst));
//         printf("\t\t|-Push Function : %d\n", ntohs((*tcp)->psh));
//         printf("\t\t|-Acknowledgment Field Significant : %d\n", ntohs((*tcp)->ack));
//         printf("\t\t|-Urgent Pointer Field Significant : %d\n", ntohs((*tcp)->urg));}
// }
//
// void process_http(){
//
// }
//
// void sniff_socket(int socket_descriptor, bool dump, struct pollfd pfd, struct ring ring){
//     UNUSED(dump);
//     socklen_t len;
//     unsigned int block_num = 0, blocks = 64;
//     struct tpacket_stats_v3 stats;
//     while (likely(!sigint)) {
//             struct block_desc * pbd = (struct block_desc *) ring.rd[block_num].iov_base;
//
//             if ((pbd->h1.block_status & TP_STATUS_USER) == 0) {
//                 poll(&pfd, 1, -1);
//                 continue;
//             }
//             walk_block(pbd);
//             flush_block(pbd);
//             block_num = (block_num + 1) % blocks;
//         }
//         len = sizeof(stats);
//         if (getsockopt(socket_descriptor, SOL_PACKET, PACKET_STATISTICS, &stats, &len) < 0) {
//             perror("getsockopt");
//             exit(1);
//         }
//
//         fflush(stdout);
//         printf("\nReceived %u packets, %lu bytes, %u dropped, freeze_q_cnt: %u\n",
//                stats.tp_packets, total_bytes, stats.tp_drops,
//                stats.tp_freeze_q_cnt);
//
//         teardown_socket(&ring, socket_descriptor);
// }
//
// void *get_socket_ready(void *arg){
//     struct thread_args *tg = (struct thread_args*) arg;
//     struct ring ring;
//     struct pollfd pfd;
//     memset(&ring, 0, sizeof(ring));
//     int socket_descriptor = create_socket(ALL);
//     set_packet_version(socket_descriptor);
//     memset(&pfd, 0, sizeof(pfd));
//     pfd.fd = socket_descriptor;
//     pfd.events = POLLIN | POLLERR;
//     pfd.revents = 0;
//     int interface_index = get_interface_index(socket_descriptor, tg->interface_name);
//     struct sockaddr_ll psll = fill_link_layer(interface_index, ALL);
//     if(tg->set_promiscuous_flag == true){
//         set_promiscuous(socket_descriptor, interface_index);
//     }
//     set_packet_rx_ring(socket_descriptor, &ring);
//     set_packet_timestamp(socket_descriptor);
//     bind_socket(socket_descriptor, psll);
//     static int fanout_type = PACKET_FANOUT_HASH;
//     int fanout_arg = (tg->fanout_id | (fanout_type << 16));
//     set_packet_fanout(socket_descriptor, fanout_arg);
//     sniff_socket(socket_descriptor,false, pfd, ring);
//     pthread_exit(0);
// }
//
//// int main(int argc, char **argv){
////     pthread_t threads[4];
////     bool set_promiscuous_flag = false;
////     bool device_list_flag = false;
////     char * interface_name = NULL;
////     int c;
////     signal(SIGINT, signal_handler);
////     while ((c = getopt (argc, argv, "pdi:")) != -1){
////         switch (c){
////           case 'p':
////             set_promiscuous_flag = true;
////             break;
////           case 'd':
////             device_list_flag = true;
////             break;
////           case 'i':
////             interface_name = optarg;
////             break;
////           case '?':
////             if (optopt == 'i'){
////               fprintf (stderr, "Option -%c requires an argument.\n", optopt);
////             }
////             else if (isprint(optopt)){
////               fprintf (stderr, "Unknown option `-%c'.\n", optopt);
////             }
////             else{
////               fprintf (stderr, "Unknown option character `\\x%x'.\n", optopt);
////             }
////             return 1;
////           default:
////             abort ();
////         }
////     }
////     if(device_list_flag == true){
////         get_af_packet_family_device_list();
////         exit(0);
////     }
////     struct thread_args* tg;
////     tg = malloc(sizeof (struct thread_args));
////     tg->interface_name = interface_name;
////     int fanout_id = getpid() & 0xffff;
////     tg->fanout_id = fanout_id;
////     tg->set_promiscuous_flag = set_promiscuous_flag;
////         for (int i = 0; i < 4; i++) {
////             pthread_create(&threads[i], NULL, get_socket_ready, (void*)tg);
////         }
////         for (int i = 0; i < 4; ++i) {
////             pthread_join(threads[i], NULL);
////         }
////         return 0;
//// }
import "C"
