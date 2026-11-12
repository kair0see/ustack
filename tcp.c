#include<stdio.h>

#include<rte_eal.h>
#include<rte_ethdev.h>
#include<rte_mbuf.h>
#include<arpa/inet.h>


#include "arp.h"

#include<rte_timer.h>
#include<rte_cycles.h>
#include<rte_lcore.h>
#include<rte_malloc.h>
#include<pthread.h>


#define ENABLE_SEND  1
#define ENABLE_ARP   1
#define ENABLE_ICMP  1
#define ENABLE_ARP_REPLY 1

#define ENABLE_DEBUG 0

#define ENABLE_TIMER     1

#define ENABLE_RINGBUFFER 1

#define ENABLE_MULTHREAD  1

#define ENABLE_UDP_APP    1

#define ENABLE_TCP_APP    1

#define NUM_BUFF (4096-1)

#define BURST_SIZE 32
#define RING_SIZE  1024


#define TIMER_RESOLUTION_CYCLES 20000000000ULL /* around 10s at 2 Ghz */
#if 1

#define MAKE_IPV4_ADDR(a,b,c,d) (a + (b<<8) + (c<<16) + (d<<24))

static uint32_t gLocalIp = MAKE_IPV4_ADDR(192,168,146,136);

static uint32_t gSrcIp;
static uint32_t gDstIp;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint16_t gSrcPort;
static uint16_t gDstPort;
#endif

#if ENABLE_ARP_REPLY

static uint8_t gDefaultArpMac[RTE_ETHER_ADDR_LEN] = {0xFF,0xFF,0xFF,0xFF,0xFF,0xFF};

#endif


#if ENABLE_RINGBUFFER

struct inout_ring{

    struct rte_ring *in;
    struct rte_ring *out;

};


static struct inout_ring *rInst = NULL;

static struct inout_ring *ring_instance(void){
    if (rInst == NULL){
        rInst = rte_malloc("in/out ring", sizeof(struct inout_ring), 0);
        if(rInst == NULL){
            rte_exit(EXIT_FAILURE, "rInst malloc failed\n");
        }
        memset(rInst, 0, sizeof(struct inout_ring));
    }
    return rInst;
};

#endif


int gDpdkPortId = 0;

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};

static int ka_udp_process(struct rte_mbuf *udpmbuf);
static int ka_udp_out(struct rte_mempool *mbuf_pool);
static int ka_tcp_process(struct rte_mbuf *tcpmbuf);
static int ka_tcp_out(struct rte_mempool *mbuf_pool);

static void ka_init_port(struct rte_mempool* mbuf_pool){
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if(nb_sys_ports == 0){
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }

    struct rte_eth_dev_info dev_info;

    rte_eth_dev_info_get(gDpdkPortId, &dev_info);

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;

    rte_eth_dev_configure(gDpdkPortId, num_rx_queues, num_tx_queues, &port_conf);


    if (rte_eth_rx_queue_setup(gDpdkPortId, 0, 128,
        rte_eth_dev_socket_id(gDpdkPortId), NULL, mbuf_pool )<0){
            rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
        }
#if ENABLE_SEND   
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;

    if (rte_eth_tx_queue_setup(gDpdkPortId, 0, 512,
        rte_eth_dev_socket_id(gDpdkPortId), &txq_conf )<0){

            rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
        }

#endif

    if (rte_eth_dev_start(gDpdkPortId) < 0){
        rte_exit(EXIT_FAILURE, "Could not start \n");
    }


}
/*
static void create_eth_ip_udp(uint8_t *msg, size_t total_len,uint8_t *dst_mac, uint32_t src_ip, 
    uint32_t dst_ip, uint16_t src_port, uint16_t dst_port){

    struct rte_ether_addr src_mac;

    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac,RTE_ETHER_ADDR_LEN);

    rte_eth_macaddr_get(gDpdkPortId, &src_mac);
    rte_memcpy(eth->s_addr.addr_bytes, src_mac,RTE_ETHER_ADDR_LEN);

    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    struct rte_ipv4_hdr *ip = (struct rte_ipv4_hdr *)(eth+1);

    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(rte_ether_hdr));
    
}
*/

static void ka_encode_udp_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len){

    //1 ethdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    //2 iphdr
    struct rte_ipv4_hdr *ip =(struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len-sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = gSrcIp;
    ip->dst_addr = gDstIp;
    
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    //3 udphdr

    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = gSrcPort;
    udp->dst_port = gDstPort;
    uint16_t udp_len = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_udp_hdr);
    udp->dgram_len = htons(total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr));

    rte_memcpy((uint8_t*)(udp+1) , data, udp_len);

    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip,udp);

   
}

static struct rte_mbuf * ka_send_udp(struct rte_mempool *mbuf_pool, unsigned char *data, uint16_t data_len){

    const unsigned total_len = data_len + 42;

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf){
        rte_exit(EXIT_FAILURE,"rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

    ka_encode_udp_pkt(pktdata, data, total_len);

    return mbuf;
}




#if ENABLE_ARP

static struct arp_table *arpt = NULL;

static int ka_encode_arp_pkt(uint8_t *msg, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip){
    // 1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    
    
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    // 2 arp
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = htons(1);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(uint32_t);
    arp->arp_opcode = htons(opcode);

    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    arp->arp_data.arp_sip = sip;
    arp->arp_data.arp_tip = dip;

    return 0;
}

#endif

#if ENABLE_ARP_REPLY
static struct arp_table *arp_table_instance(void){
    
    if(arpt == NULL){
        arpt = rte_malloc("arp table",sizeof(struct arp_table), 0);
        
        if(arpt == NULL){
            rte_exit(EXIT_FAILURE,"rte_malloc arp table failed\n");
        }
        memset(arpt, 0, sizeof(struct arp_table));
    }
    
    return arpt;
}


static uint8_t* ka_get_dst_macaddr(uint32_t dip){

    struct arp_entry *iter;
    struct arp_table *table = arp_table_instance();

    for(iter = table->entries; iter != NULL; iter =iter->next){
        if(dip == iter->ip){
            return iter->hwaddr;
        }
    }

    return NULL;


}

static struct rte_mbuf * ka_send_arp(struct rte_mempool *mbuf_pool, uint16_t opcode, uint8_t *dst_mac, uint32_t sip, uint32_t dip){

    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf){
        rte_exit(EXIT_FAILURE,"rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ka_encode_arp_pkt(pkt_data, opcode, dst_mac, sip, dip);

    return mbuf;

} 


#endif



#if ENABLE_ICMP

static uint16_t rte_ipv4_icmp_cksum(uint16_t *addr, int count){

    register long sum = 0;

    while(count > 1){
        sum += *(unsigned short *)addr++; 
        count -=2;

    }
    if(count > 0){
        sum += *(unsigned char *)addr; 
    }
    while(sum >> 16){
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;

}


static int ka_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac,
    uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb){

    //1 ethdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    //2 iphdr
    struct rte_ipv4_hdr *ip =(struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_ICMP;
    ip->src_addr = sip;
    ip->dst_addr = dip;
    
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    //3 icmp
    struct rte_icmp_hdr *icmp = (struct rte_icmp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmp->icmp_code = 0;
    icmp->icmp_ident = id;
    icmp->icmp_seq_nb = seqnb;
    
    icmp->icmp_cksum = 0;
    icmp->icmp_cksum = rte_ipv4_icmp_cksum((uint16_t *)icmp, sizeof(struct rte_icmp_hdr));

    return 0;
    }


static struct rte_mbuf *ka_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
    uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb){

    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);
    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf){
        rte_exit(EXIT_FAILURE,"rte_pktmbuf_alloc\n");
    }
        
    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ka_encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seqnb);

    return mbuf;
}

#endif

static  void print_etheraddr(const char *name,const struct rte_ether_addr *eth_addr){

    char buf[RTE_ETHER_ADDR_FMT_SIZE];
    rte_ether_format_addr(buf, RTE_ETHER_ADDR_FMT_SIZE, eth_addr);
    printf("%s%s\n", name, buf);
}    

#if ENABLE_TIMER

static void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim,
	  __attribute__((unused)) void *arg){//timer0_cb

    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;
    struct inout_ring * ring = ring_instance();
#if 0
    struct rte_mbuf *arpbuf = ka_send_arp(mbuf_pool, ahdr->arp_data.arp_sha.addr_bytes,
        ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

    rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
    rte_pktmbuf_free(arpbuf);
#endif
    for(int i = 1;i <=254; i++){

        uint32_t dstip = (gLocalIp & 0x00FFFFFF) | (0xFF000000 & (i << 24));
        //struct in_addr addr;
        //addr.s_addr = dstip;
        //printf("arp ---> src:%s \n",inet_ntoa(addr));

        struct rte_mbuf *arpbuf = NULL;
        uint8_t *dstmac =  ka_get_dst_macaddr(dstip);

        if(dstmac==NULL){

           arpbuf = ka_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac, gLocalIp, dstip);

        }else{

            arpbuf = ka_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, dstmac, gLocalIp, dstip);
        }

        if (i == 1) {
            struct rte_ether_hdr *eth = rte_pktmbuf_mtod(arpbuf, struct rte_ether_hdr *);

            //print_etheraddr("ARP发送目标MAC:", &eth->d_addr);
        }

        //rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
        //rte_pktmbuf_free(arpbuf);
        rte_ring_mp_enqueue_burst(ring->out, (void**)&arpbuf, 1,NULL);
    }

}

#endif

#if ENABLE_MULTHREAD

static int pkt_process(__attribute__((unused)) void *arg){

    //printf("main <--> pkt_process\n");

    struct in_addr addr;

    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg; 
    struct inout_ring *ring = ring_instance();

    while(1){

        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned num_recvd = rte_ring_mc_dequeue_burst(ring->in, (void**)mbufs, BURST_SIZE, NULL);
       
        unsigned i = 0;

        for(i =0;i < num_recvd; i++){

            struct rte_ether_hdr *ehdr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

#if ENABLE_ARP

            if(ehdr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)){
               
                struct rte_arp_hdr *ahdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_arp_hdr *, sizeof(struct rte_ether_hdr));

                //addr.s_addr = ahdr->arp_data.arp_tip;
                //printf("arp ---> src:%s ",inet_ntoa(addr));

                //addr.s_addr = gLocalIp;
                //printf("local: %s\n",inet_ntoa(addr));

    

                if(ahdr->arp_data.arp_tip == gLocalIp){

                    if(ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)){ 

                        //printf("arp --> reply\n");

                        struct rte_mbuf *arpbuf = ka_send_arp(mbuf_pool, RTE_ARP_OP_REPLY,ahdr->arp_data.arp_sha.addr_bytes,
                            ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

                        //rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
                        //rte_pktmbuf_free(arpbuf);
                        //rte_pktmbuf_free(mbufs[i]);
                        rte_ring_mp_enqueue_burst(ring->out, (void**)arpbuf, 1, NULL);
                        
                    }else if(ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)){

                        //printf("arp --> request\n");

                        uint8_t *hwaddr = ka_get_dst_macaddr(ahdr->arp_data.arp_sip);
                        struct arp_table *table = arp_table_instance();

                        if(hwaddr == NULL){
                            
                            struct arp_entry *entry = rte_malloc("arp entry", sizeof(struct arp_entry), 0);
                            if(entry){
                                
                                memset(entry, 0, sizeof(struct arp_entry));
                                entry->ip = ahdr->arp_data.arp_sip;

                                rte_memcpy(entry->hwaddr, ahdr->arp_data.arp_sha.addr_bytes, RTE_ETHER_ADDR_LEN);
                                entry->status = ARP_ENTRY_STATUS_DYNAMIC;

                                LL_ADD(entry, table->entries);
                                table->count ++;// cas


                            }
                        }

#if ENABLE_DEBUG

                        struct arp_entry *iter;
                         for(iter = table->entries; iter != NULL; iter =iter->next){
                            print_etheraddr("arp entry --> mac: ", (struct rte_ether_addr *)iter->hwaddr);
                            
                            addr.s_addr = iter->ip;
                            printf("arp ---> src: %s\n",inet_ntoa(addr));
                        }
                        rte_pktmbuf_free(mbufs[i]);
        
#endif
                    }
                    
                    
                }

                continue;
            }
#endif

            if(ehdr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)){
                continue;
            }

            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
            if(iphdr->next_proto_id == IPPROTO_UDP){

                struct rte_udp_hdr *udphdr =  (struct rte_udp_hdr*) (iphdr + 1);

#if ENABLE_SEND

                rte_memcpy(gDstMac, ehdr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN); 

                rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
                rte_memcpy(&gDstIp, &iphdr->src_addr, sizeof(uint32_t));

                rte_memcpy(&gSrcPort,&udphdr->dst_port,sizeof(u_int16_t));
                rte_memcpy(&gDstPort,&udphdr->src_port,sizeof(u_int16_t));
#endif

                uint16_t udp_len = ntohs(udphdr->dgram_len);
                *((char *)udphdr + udp_len) = '\0';


                //addr.s_addr = iphdr->src_addr;
                //printf("src:%s:%d, ",inet_ntoa(addr),ntohs(udphdr->src_port));

                //addr.s_addr = iphdr->dst_addr;
                //printf("dst:%s:%d,  %s\n ",inet_ntoa(addr),ntohs(udphdr->dst_port),(char *)(udphdr+1));


#if ENABLE_SEND 
                uint16_t data_len = udp_len - sizeof(struct rte_udp_hdr);
                struct rte_mbuf* txbuf = ka_send_udp(mbuf_pool, (unsigned char *)(udphdr+1), data_len);
                //rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
                //rte_pktmbuf_free(txbuf);
                rte_ring_mp_enqueue_burst(ring->out, (void**)&txbuf, 1,NULL);
                

#endif

             


                
            }

#if ENABLE_ICMP

            if(iphdr->next_proto_id == IPPROTO_ICMP){
                struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

                addr.s_addr = iphdr->src_addr;
                printf("icmp ---> src:%s ",inet_ntoa(addr));

                addr.s_addr = iphdr->dst_addr;
                printf("local: %s ,type:%d\n",inet_ntoa(addr),icmphdr->icmp_type);
                
                if(icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST){
                    
                    struct rte_mbuf *txbuf = ka_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes, iphdr->dst_addr,
                        iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
                    
                    //rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
                    //rte_pktmbuf_free(txbuf);
                    rte_ring_mp_enqueue_burst(ring->out, (void**)&txbuf, 1,NULL);
                    rte_pktmbuf_free(mbufs[i]);
                }

                
            }


#endif


#if ENABLE_UDP_APP
            if(iphdr->next_proto_id == IPPROTO_UDP){
             
                ka_udp_process(mbufs[i]);
            
            }

#endif


#if ENABLE_TCP_APP
            
            if(iphdr->next_proto_id == IPPROTO_TCP){
                //printf("into tcp ?\n");
                ka_tcp_process(mbufs[i]);
            
            }
#endif


        }
#if ENABLE_UDP_APP

    ka_udp_out(mbuf_pool);
 
#endif

#if ENABLE_TCP_APP

    ka_tcp_out(mbuf_pool);

#endif

    }
    return 0;
}

#endif


#if ENABLE_UDP_APP


#define HOST_BLOCK       0
#define HOST_NON_BLOCK   1

#define UDP_APP_RECV_BUFFER 128
#define DEFAULT_FD           3

struct localhost{

    int fd;
    uint32_t local_ip;
    uint16_t local_port;
    uint8_t local_mac[RTE_ETHER_ADDR_LEN];

    uint8_t protocol;

    struct rte_ring *rcvbuf;
    struct rte_ring *sndbuf;

    struct localhost *prev;
    struct localhost *next;

    int status;

    pthread_cond_t cond;
    pthread_mutex_t mutex;

};


struct offload{

    uint32_t sip;
    uint32_t dip;

    uint16_t sport;
    uint16_t dport;

    int protocol;

    unsigned char *data;
    uint32_t length;

};

int globalfd = DEFAULT_FD;

struct localhost *lhost = NULL;



static int get_fd_from_bitmap(void){
    
    return globalfd++;

} 

static struct localhost * get_hostinfo_from_fd(int sockfd){
    struct localhost * host;
    for(host = lhost; host != NULL; host= host->next){
        if(host->fd == sockfd){
            return host;
        }
    }
    return NULL;
}

static struct localhost * get_hostinfo_fromip_port(uint32_t dip, uint64_t dport, uint8_t protocol){

    struct localhost * host;
    for(host = lhost; host != NULL; host= host->next){
        if((host->local_ip == dip || host->local_ip == htons(INADDR_ANY))  && host->local_port == dport && host->protocol == protocol){
            return host;
        }
    }
    return NULL; 
}



static int nsocket(int domain,int type, int protocol){
    
    int fd = get_fd_from_bitmap();
    if(fd < 0){
        return -1;
    }

    struct localhost* host = (struct localhost*)malloc(sizeof(struct localhost));
    if(host == NULL){
        return -1;
    }
    memset(host, 0, sizeof(struct localhost));

    host->fd = fd;

    if(type == SOCK_DGRAM){
        host->protocol = IPPROTO_UDP;
    }else if(type == SOCK_STREAM){
        host->protocol = IPPROTO_TCP;
    }

    host->rcvbuf = rte_ring_create("recv buffer", RING_SIZE, rte_socket_id(),RING_F_SC_DEQ | RING_F_SP_ENQ);
    
    if(host->rcvbuf == NULL){
        free(host);
        return -1;
    }
    host->sndbuf = rte_ring_create("send buffer", RING_SIZE, rte_socket_id(),RING_F_SC_DEQ | RING_F_SP_ENQ);
    if(host->sndbuf == NULL){
        rte_ring_free(host->rcvbuf);
        free(host);
        return -1;
    }
    pthread_cond_t blank_cond = PTHREAD_COND_INITIALIZER;
    rte_memcpy(&host->cond, &blank_cond, sizeof(pthread_cond_t));
     
    pthread_mutex_t blank_mutex = PTHREAD_MUTEX_INITIALIZER;
    rte_memcpy(&host->mutex, &blank_mutex, sizeof(pthread_mutex_t));
    
    LL_ADD(host, lhost);
    
    return fd;
}


static int nbind(int socket,  struct sockaddr_in *addr, socklen_t addrlen){
    struct localhost *host = get_hostinfo_from_fd(socket);
    if(host == NULL){
        return -1;
    }
    struct sockaddr_in* laddr =(struct sockaddr_in *) addr;
    host->local_port = laddr->sin_port;
    rte_memcpy(&host->local_ip, &laddr->sin_addr.s_addr, sizeof(uint32_t));
    rte_memcpy(&host->local_mac, &gSrcMac, RTE_ETHER_ADDR_LEN);

    return 0;

}


static int nrecv_from(int sockfd, void* buf, size_t len, int flags, 
    struct sockaddr_in *src_addr){
    
    void * obj =NULL;
    struct offload *ol = NULL;
    int nb = -1;
    struct sockaddr_in *saddr = (struct sockaddr_in *)src_addr;
    unsigned char *ptr = NULL;
    
    struct localhost *host = get_hostinfo_from_fd(sockfd);

    if(host == NULL)return -1;
    
    pthread_mutex_lock(&host->mutex);
    while((nb = rte_ring_mc_dequeue(host->rcvbuf, &obj)) < 0){
        pthread_cond_wait(&host->cond, &host->mutex);
    }
    ol = obj;
    pthread_mutex_unlock(&host->mutex);
    
    
    saddr->sin_port = ol->sport;
    rte_memcpy(&saddr->sin_addr.s_addr, &ol->sip, sizeof(uint32_t));

    if(len < ol->length){
        rte_memcpy(buf, ol->data, len);

        ptr = rte_malloc("unsigned char *",ol->length - len, 0);
        rte_memcpy(ptr, ol->data+len, ol -> length-len);
        rte_free(ol->data);
        ol->data = ptr;

        rte_ring_mp_enqueue(host->rcvbuf, ol);

        pthread_mutex_lock(&host->mutex);
        pthread_cond_signal(&host->cond);
        pthread_mutex_unlock(&host->mutex);
        
        return len;
    }else{
        rte_memcpy(buf, ol->data, ol->length);

        rte_free(ol->data);
        rte_free(ol);

        return ol->length;
    }

}

//app buf --> host->snd_buf
static int nsend_to(int sockfd, void* buf, size_t len, int flags, 
    struct sockaddr_in *dst_addr, socklen_t addr_len){

    //printf("enter nsend_to\n");
    struct localhost *host = get_hostinfo_from_fd(sockfd);
    if(host == NULL)return -1;

    struct sockaddr_in *daddr = (struct sockaddr_in *)dst_addr;

    struct offload *ol = rte_malloc("offload", sizeof(struct offload), 0);
    if(ol == NULL) return -1;

    ol->dip = daddr->sin_addr.s_addr;
    ol->dport = daddr->sin_port;
    ol->sip = host->local_ip;
    ol->sport = host->local_port;
    ol->length = len;

    ol->data = rte_malloc("unsigned char *", len, 0);
    if(ol->data == NULL){
        rte_free(ol);
        return -1;
    }

    rte_memcpy(ol->data, buf, len);

    int ret = rte_ring_mp_enqueue(host->sndbuf,ol);
    //printf("nsend_to suceess or not :%d\n", ret);
    return len;
}

static int nclose(int fd){

    struct localhost *host = get_hostinfo_from_fd(fd);
    LL_REMOVE(host,lhost);
    if(host->rcvbuf){
        rte_ring_free(host->rcvbuf);
    }
    if(host->sndbuf){
      rte_ring_free(host->sndbuf);  
    }
    free(host);        
        
    return 0;

}


static int ka_udp_process(struct rte_mbuf *udpmbuf){

    //printf("pkt_process --> udp_process\n");
    
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(udpmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_udp_hdr *udphdr =  (struct rte_udp_hdr*) (iphdr + 1);
    
    struct localhost *host = get_hostinfo_fromip_port(iphdr->dst_addr, udphdr->dst_port, iphdr->next_proto_id);


    if(host == NULL){
        rte_pktmbuf_free(udpmbuf);
        return -3;
    }

    struct offload *ol = rte_malloc("recv offload", sizeof(struct offload), 0);
    if(ol == NULL)return -1;

    ol->dip = iphdr->dst_addr;
    ol->sip = iphdr->src_addr;
    ol->sport = udphdr->src_port;
    ol->dport = udphdr->dst_port;

    ol->protocol = IPPROTO_UDP;
    ol->length = ntohs(udphdr->dgram_len);

    ol->data = rte_malloc("unsigned char*", ol->length-sizeof(struct rte_udp_hdr), 0);
    if(ol->data == NULL){
        
        rte_pktmbuf_free(udpmbuf);
        rte_free(ol);

        return -2;
    }
    rte_memcpy(ol->data, udphdr+1, ol->length); 

    rte_ring_mp_enqueue(host->rcvbuf, ol);

    pthread_mutex_lock(&host->mutex);
    pthread_cond_signal(&host->cond);
    pthread_mutex_unlock(&host->mutex);

    rte_pktmbuf_free(udpmbuf);
    return 0;

}

static void ka_encode_udp_app_pkt(uint8_t *msg, unsigned char *data, uint16_t total_len, uint32_t sip,
    uint32_t dip, uint16_t sport, uint16_t dport, const uint8_t *srcmac, const uint8_t *dstmac){

    //1 ethdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    //2 iphdr
    struct rte_ipv4_hdr *ip =(struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len-sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = sip;
    ip->dst_addr = dip;
    
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    //3 udphdr

    struct rte_udp_hdr *udp = (struct rte_udp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = sport;
    udp->dst_port = dport;
    uint16_t udp_len = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr) - sizeof(struct rte_udp_hdr);
    udp->dgram_len = htons(total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr));

    rte_memcpy((uint8_t*)(udp+1) , data, udp_len);

    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip,udp);

    
}

static struct rte_mbuf * ka_udp_pkt(struct rte_mempool *mbuf_pool, unsigned char *data, uint16_t data_len, uint32_t sip,
    uint32_t dip, uint16_t sport, uint16_t dport, const uint8_t* srcmac,const uint8_t* dstmac){

    const unsigned total_len = data_len + 42;

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf){
        rte_exit(EXIT_FAILURE,"rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

    ka_encode_udp_app_pkt(pktdata, data, total_len, sip, dip, sport, dport, srcmac, dstmac);

    return mbuf;
}




//host->snd ---> mbuf 
static int ka_udp_out(struct rte_mempool *mbuf_pool){

    //printf("pkt_process --> udp_out\n");
    struct localhost *host;
    for(host = lhost; host != NULL; host = host->next){

        void * obj = NULL;
        struct offload *ol = NULL;
        
        int nb_send = rte_ring_mc_dequeue(host->sndbuf, &obj);
        if(nb_send < 0)continue;
        //printf("udp_out: snd_buff,dequeue\n");
        
        ol = obj;
        uint8_t *dstmac = ka_get_dst_macaddr(ol->dip);
        if(dstmac == NULL){
        struct rte_mbuf *arpbuf = ka_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac,
            ol->sip, ol->dip);
        
        struct inout_ring *ring = ring_instance();
        rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
        
        rte_ring_mp_enqueue(host->sndbuf, ol);
        }else{

            struct rte_mbuf *udpbuf = ka_udp_pkt(mbuf_pool, ol->data, ol->length, ol->sip, ol->dip, 
                ol->sport, ol->dport, host->local_mac, dstmac);
            //rte_pktmbuf_dump(stderr, udpbuf, rte_pktmbuf_pkt_len(udpbuf));
            struct inout_ring *ring = ring_instance();
            rte_ring_mp_enqueue_burst(ring->out, (void **)&udpbuf, 1, NULL);
            //printf("udp_out: ring->out, enqueue\n");
        }
        
    }
    return 0;

    
}




static int udp_server_entry(void* argc){

    //printf("udp_process <--> udp_server\n");
    int connfd = nsocket(AF_INET, SOCK_DGRAM, 0);
    if(connfd == -1){
        printf( "sockfd failed\n");
        return -1;
    }

    struct sockaddr_in localaddr, clientaddr;//struct sockaddr 14Byte
    memset(&localaddr, 0, sizeof(struct sockaddr_in));

    localaddr.sin_port = htons(9999);
    localaddr.sin_family = AF_INET;
    localaddr.sin_addr.s_addr = inet_addr("192.168.146.136");
    //localaddr.sin_addr.s_addr = htons(INADDR_ANY);//0.0.0.0

    nbind(connfd, &localaddr, sizeof(localaddr));

    char buffer[128] = {0};
    socklen_t addrlen;
    while(1){
        if(nrecv_from(connfd, buffer, UDP_APP_RECV_BUFFER,
            0, &clientaddr)<0){
                continue;
            }else{

                printf("two ring recv from %s:%d,data:%s\n", inet_ntoa(clientaddr.sin_addr), 
                    ntohs(clientaddr.sin_port),buffer);
                nsend_to(connfd, buffer, strlen(buffer), 0,&clientaddr, sizeof(clientaddr));
            }
    }

    nclose(connfd);
}


#endif

#if ENABLE_TCP_APP

#define TCP_OPTION_LEN    10

#define TCP_MAX_SEQ      4294967295

#define TCP_INITIAL_WINDOW 14600

typedef enum ka_tcp_status{
    KA_TCP_STATUS_CLOSED = 0,
    KA_TCP_STATUS_LISTEN,
    KA_TCP_STATUS_SYN_RCVD,
    KA_TCP_STATUS_SYN_SENT,
    KA_TCP_STATUS_ESTABLISHED,
    
    KA_TCP_STATUS_FIN_WAIT_1,
    KA_TCP_STATUS_FIN_WAIT_2,
    KA_TCP_STATUS_CLOSING,
    KA_TCP_STATUS_TIME_WAIT,
    
    KA_TCP_STATUS_CLOSE_WAIT,
    KA_TCP_STATUS_LAST_ACK
}ka_tcp_status;

struct ka_tcp_stream{

    int fd;

    uint32_t sip;
    uint32_t dip;
    uint16_t sport;
    uint16_t dport;
    uint16_t proto;

    uint8_t localmac[RTE_ETHER_ADDR_LEN];
    
    struct ka_tcp_stream *prev;
    struct ka_tcp_stream *next;

    uint32_t snd_una;
    uint32_t snd_nxt;
    uint32_t rcv_nxt;

    struct rte_ring *rcvbuf;
    struct rte_ring *sndbuf;

    ka_tcp_status status;
};


struct ka_tcp_fragment{
    
    rte_be16_t sport; /**< TCP source port. */
	rte_be16_t dport; /**< TCP destination port. */
	rte_be32_t seqnum; /**< TX data sequence number. */
	rte_be32_t acknum; /**< RX data acknowledgment sequence number. */
	uint8_t  head_len;   /**< Data offset. */
	uint8_t  tcp_flags;  /**< TCP flags */
	rte_be16_t rx_win;   /**< RX flow control window. */
	rte_be16_t cksum;    /**< TCP checksum. */
	rte_be16_t tcp_urp;  /**< TCP urgent pointer, if any. */ 
    uint32_t option[TCP_OPTION_LEN];
    uint32_t option_len;

    unsigned char* data;
    uint32_t length;
};


struct ka_tcp_table{
    int count;
    struct ka_tcp_stream *tcp_set;
};

struct ka_tcp_table *tInst = NULL;

static struct ka_tcp_table *tcp_instance(void){
    if(tInst == NULL){

        tInst = rte_malloc("tcp table", sizeof(struct ka_tcp_table), 0);
        if(tInst == NULL)return NULL;
        memset(tInst, 0, sizeof(struct ka_tcp_table));

    }
    return tInst;
}


static struct ka_tcp_stream *ka_tcp_stream_serch(uint32_t sip, uint32_t dip, uint16_t sport,uint16_t dport){
    struct ka_tcp_table *table = tcp_instance();

    struct ka_tcp_stream *iter;
    for(iter = table->tcp_set; iter != NULL; iter = iter->next){
        if(iter->sip == sip && iter->dip == dip && iter->sport == sport && iter->dport == dport){
            return iter;
        }
    }
    return NULL;

}

static struct ka_tcp_stream *ka_tcp_stream_create(uint32_t sip, uint32_t dip, uint16_t sport,uint16_t dport){

    //tcp -->status
    struct ka_tcp_stream *stream = rte_malloc("ka_tcp_stream", sizeof(struct ka_tcp_stream), 0);
    if(stream == NULL)return NULL;

    stream->sip = sip;
    stream->dip = dip;
    stream->sport = sport;
    stream->dport = dport;
    stream->proto = IPPROTO_TCP;

    stream->status = KA_TCP_STATUS_LISTEN;
    
    stream->sndbuf = rte_ring_create("sndbuf", RING_SIZE, rte_socket_id(), 0);
    stream->rcvbuf = rte_ring_create("rcvbuf", RING_SIZE, rte_socket_id(), 0);
//seq num
    uint32_t next_send = time(NULL);
    stream->snd_nxt = rand_r(&next_send) % TCP_MAX_SEQ;
    rte_memcpy(stream->localmac , gSrcMac, RTE_ETHER_ADDR_LEN);

    struct ka_tcp_table *table = tcp_instance();
    LL_ADD(stream , table->tcp_set);
    
    return stream;

}

static int ka_tcp_handle_listen(struct ka_tcp_stream *stream, struct rte_tcp_hdr *tcphdr){

    if(tcphdr->tcp_flags & RTE_TCP_SYN_FLAG){
        if(stream->status == KA_TCP_STATUS_LISTEN){

            struct ka_tcp_fragment *fragment = rte_malloc("tcp_fragment", sizeof(struct ka_tcp_fragment), 0);
            if(fragment == NULL)return -1;
            memset(fragment, 0, sizeof(struct ka_tcp_fragment));
            
            fragment->sport = tcphdr->dst_port;
            fragment->dport = tcphdr->src_port;

            stream->rcv_nxt = ntohl(tcphdr->sent_seq) + 1;
            
            fragment->seqnum = htonl(stream->snd_nxt);
            fragment->acknum = htonl(stream->rcv_nxt);

            fragment->tcp_flags = RTE_TCP_SYN_FLAG | RTE_TCP_ACK_FLAG;
            fragment->rx_win = htons(TCP_INITIAL_WINDOW);
            fragment->head_len = 0x50;
            fragment->data = NULL;
            fragment->length = 0;
            
            stream->snd_nxt++;
            stream->status = KA_TCP_STATUS_SYN_RCVD;
            printf("syn --> tcp server\n");
            rte_ring_mp_enqueue(stream->sndbuf, fragment);
        }
        
    }
    return 0;

}
static int ka_tcp_handle_syn_rcvd(struct ka_tcp_stream *stream, struct rte_tcp_hdr *tcphdr){

    if(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG){
        if(stream->status == KA_TCP_STATUS_SYN_RCVD){

           uint32_t acknum = ntohl(tcphdr->recv_ack);
           if(acknum == stream->snd_nxt ){
                stream->status = KA_TCP_STATUS_ESTABLISHED;
           }
        }
    }
    return 0;

}

static int ka_tcp_handle_established(struct ka_tcp_stream *stream, struct rte_tcp_hdr *tcphdr ,int tcplen){
    if(tcphdr->tcp_flags & RTE_TCP_SYN_FLAG){

    }

    if(tcphdr->tcp_flags & RTE_TCP_PSH_FLAG){
        // rcv pkt
        struct ka_tcp_fragment *rfragment = rte_malloc("ka_tcp_fragment", sizeof(struct ka_tcp_fragment), 0);
        if(rfragment == NULL)return -1;
        memset(rfragment, 0, sizeof(struct ka_tcp_fragment));

        rfragment->dport = tcphdr->dst_port;
        rfragment->sport = tcphdr->src_port;

        uint8_t hdrlen = tcphdr->data_off >> 4;
        int payloadlen = tcplen - hdrlen*4;
        if(payloadlen > 0){
    
            uint8_t *payload = (uint8_t*)tcphdr + hdrlen * 4;

            rfragment->data = rte_malloc("unsigned char *", payloadlen + 1, 0);
            if(rfragment->data == NULL){
                rte_free(rfragment);
                return -1;
            }
            memset(rfragment->data, 0, payloadlen);

            rte_memcpy(rfragment->data, payload, payloadlen + 1);
            rfragment->length = payloadlen;

            printf("tcp : %s\n", payload);
        }
        rte_ring_mp_enqueue(stream->rcvbuf, rfragment);


        //ack pkt
        struct ka_tcp_fragment *ackfrag = rte_malloc("ka_tcp_fragment", sizeof(struct ka_tcp_fragment), 0);
        if(ackfrag == NULL) return -1;
        memset(ackfrag, 0, sizeof(struct ka_tcp_fragment));

        ackfrag->dport = tcphdr->src_port;
        ackfrag->sport = tcphdr->dst_port;

        //remote
        if(stream->snd_nxt != ntohs(tcphdr->sent_seq)){

        };
        printf("ka_tcp_handle_established: %d, %d\n",stream->rcv_nxt,ntohs(tcphdr->sent_seq));
        
        stream->rcv_nxt = stream->rcv_nxt + payloadlen;
        stream->snd_nxt = ntohl(tcphdr->recv_ack);
        stream->snd_una = ntohl(tcphdr->recv_ack); 

        ackfrag->seqnum = htonl(stream->snd_nxt);
        ackfrag->acknum = htonl(stream->rcv_nxt);

        ackfrag->tcp_flags = RTE_TCP_ACK_FLAG;
        ackfrag->rx_win = htons(TCP_INITIAL_WINDOW);
        ackfrag->head_len = 0x50;
        ackfrag->data = NULL;
        ackfrag->length = 0;
        rte_ring_mp_enqueue(stream->sndbuf, ackfrag);

        
        //echo pkt
        struct ka_tcp_fragment *echofrag = rte_malloc("ka_tcp_fragment", sizeof(struct ka_tcp_fragment), 0);
        if(echofrag == NULL) return -1;
        memset(echofrag, 0, sizeof(struct ka_tcp_fragment));

        echofrag->dport = tcphdr->src_port;
        echofrag->sport = tcphdr->dst_port;
        echofrag->seqnum = htonl(stream->snd_nxt);
        echofrag->acknum = htonl(stream->rcv_nxt);

        echofrag->tcp_flags = RTE_TCP_ACK_FLAG | RTE_TCP_PSH_FLAG;
        echofrag->rx_win = htons(TCP_INITIAL_WINDOW);
        echofrag->head_len = 0x50;

        uint8_t *payload = (uint8_t*)tcphdr + hdrlen * 4;

        echofrag->data = rte_malloc("unsigned char *", payloadlen, 0);
        if(echofrag->data == NULL){
            rte_free(echofrag);
            return -1;
        }
        memset(echofrag->data, 0, payloadlen);

        rte_memcpy(echofrag->data, payload, payloadlen);
        echofrag->length = payloadlen;

        rte_ring_mp_enqueue(stream->sndbuf, echofrag);

        
    }
    
    if(tcphdr->tcp_flags & RTE_TCP_ACK_FLAG){

    }
    if(tcphdr->tcp_flags & RTE_TCP_FIN_FLAG){
        stream->status = KA_TCP_STATUS_CLOSE_WAIT;
    }
    return 0;
}



static int ka_tcp_process(struct rte_mbuf *tcpmbuf){
    struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(tcpmbuf, struct rte_ipv4_hdr *, sizeof(struct rte_ether_hdr));
    struct rte_tcp_hdr *tcphdr =  (struct rte_tcp_hdr*) (iphdr + 1);
    
    uint16_t tcpcksum = tcphdr->cksum;
    tcphdr->cksum = 0;
    uint16_t cksum = rte_ipv4_udptcp_cksum(iphdr, tcphdr);
    if(cksum != tcpcksum){
        return -1;
    }
    tcphdr->cksum = tcpcksum;

    struct ka_tcp_stream *stream = ka_tcp_stream_serch(iphdr->src_addr,iphdr->dst_addr,tcphdr->src_port,tcphdr->dst_port);
    if(stream == NULL){
        stream = ka_tcp_stream_create(iphdr->src_addr,iphdr->dst_addr,tcphdr->src_port,tcphdr->dst_port);
        if(stream == NULL)return -2;
    }


    switch(stream->status){

        case KA_TCP_STATUS_CLOSED://client/server
            break;

        case KA_TCP_STATUS_LISTEN:{//server
            ka_tcp_handle_listen(stream, tcphdr);
            break;
        }
        case KA_TCP_STATUS_SYN_RCVD:{ //server
            ka_tcp_handle_syn_rcvd(stream, tcphdr);
            break;
        }
        case KA_TCP_STATUS_SYN_SENT://client
            break;    

        case KA_TCP_STATUS_ESTABLISHED:{//client/server

            int tcplen = ntohs(iphdr->total_length) - sizeof(struct rte_ipv4_hdr);

            ka_tcp_handle_established(stream, tcphdr, tcplen);

            break;
        }
        case KA_TCP_STATUS_FIN_WAIT_1://~client
            break;

        case KA_TCP_STATUS_FIN_WAIT_2://~client
            break;

        case KA_TCP_STATUS_CLOSING://~client
            break;

        case KA_TCP_STATUS_TIME_WAIT://~client
            break;
            
        case KA_TCP_STATUS_CLOSE_WAIT://~server
            break;

        case KA_TCP_STATUS_LAST_ACK://~server
            break;
    }
    return 0;
}


static void ka_encode_tcp_pkt(uint8_t *msg,  uint32_t sip,uint32_t dip, const uint8_t *srcmac, const uint8_t *dstmac, struct ka_tcp_fragment *fragment){

    const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) 
        +sizeof(struct rte_tcp_hdr)+fragment->option_len;


    //1 ethdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, srcmac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dstmac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    //2 iphdr
    struct rte_ipv4_hdr *ip =(struct rte_ipv4_hdr *)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x45;
    ip->type_of_service = 0;
    ip->total_length = htons(total_len-sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_TCP;
    ip->src_addr = sip;
    ip->dst_addr = dip;
    
    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    //3 tcphdr

    struct rte_tcp_hdr *tcp = (struct rte_tcp_hdr *)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    tcp->src_port = fragment->sport;
    tcp->dst_port = fragment->dport;
    tcp->sent_seq = fragment->seqnum;
    tcp->recv_ack = fragment->acknum;

    tcp->data_off = fragment->head_len;
    tcp->rx_win =fragment->rx_win;
    tcp->tcp_urp = fragment->tcp_urp;

    tcp->tcp_flags = fragment->tcp_flags;

    if(fragment->data != NULL){
        uint8_t *payload = (uint8_t*)(tcp+1) + fragment->option_len;
        rte_memcpy(payload, fragment->data, fragment->length);
        
    }
    tcp->cksum = 0;
    tcp->cksum = rte_ipv4_udptcp_cksum(ip,tcp);
   

}




static struct rte_mbuf * ka_tcp_pkt(struct rte_mempool *mbuf_pool,uint32_t sip,
    uint32_t dip,const uint8_t* srcmac,const uint8_t* dstmac,struct ka_tcp_fragment *fragment){

    const unsigned total_len = fragment->length + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) 
        +sizeof(struct rte_tcp_hdr)+fragment->option_len;

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if(!mbuf){
        rte_exit(EXIT_FAILURE,"rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

    ka_encode_tcp_pkt(pktdata, sip, dip, srcmac, dstmac ,fragment);

    return mbuf;
}




static int ka_tcp_out(struct rte_mempool *mbuf_pool){
    struct ka_tcp_table *table = tcp_instance();
    struct ka_tcp_stream *stream;

    for(stream = table->tcp_set; stream != NULL; stream = stream->next){

        void *obj = NULL;
        struct ka_tcp_fragment *fragment;
        int nb_snd = rte_ring_mc_dequeue(stream->sndbuf, &obj);
        if(nb_snd < 0) continue;
        fragment = obj;
        uint8_t *dstmac = ka_get_dst_macaddr(stream->sip);
        if(dstmac == NULL){

            struct rte_mbuf *arpbuf = ka_send_arp(mbuf_pool, RTE_ARP_OP_REQUEST, gDefaultArpMac,
                stream->dip, stream->sip);
            
            struct inout_ring *ring = ring_instance();

            rte_ring_mp_enqueue_burst(ring->out, (void **)&arpbuf, 1, NULL);
            
            
            rte_ring_mp_enqueue(stream->sndbuf, fragment);
        }else{
            struct rte_mbuf *tcpbuf = ka_tcp_pkt(mbuf_pool, stream->dip, stream->sip, stream->localmac, dstmac, fragment);
            
            struct inout_ring *ring = ring_instance();

            rte_ring_mp_enqueue_burst(ring->out, (void**)&tcpbuf, 1, NULL);
            printf("syn --> client\n");
            if(fragment->data != NULL){
                rte_free(fragment->data);
            }
            rte_free(fragment);

        }
        
    }
    return 0;
}



#endif



int main(int argc, char* argv[]){
    

    if(rte_eal_init(argc, argv) < 0){
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_BUFF,
        0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());

    if(mbuf_pool == NULL){
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    ka_init_port(mbuf_pool);

    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);

    


#if ENABLE_TIMER
    rte_timer_subsystem_init();
    struct rte_timer arp_timer;
    
    rte_timer_init(&arp_timer);

    uint64_t hz = rte_get_timer_hz();
    unsigned lcore_id = rte_lcore_id();

	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);

#endif



#if ENABLE_RINGBUFFER

    struct inout_ring *ring = ring_instance();
    if(ring == NULL){
        rte_exit(EXIT_FAILURE, "ring buffer init failed\n");
    }

    if(ring->in == NULL){
        
        ring->in = rte_ring_create("in ring", RING_SIZE, rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
        if (ring->in == NULL){
            rte_exit(EXIT_FAILURE, "Failed to create input ring\n");
        } 
    }
    if(ring->out == NULL){
        ring->out = rte_ring_create("out ring", RING_SIZE, rte_socket_id(), RING_F_SC_DEQ | RING_F_SP_ENQ);
        if (ring->out == NULL){
            rte_exit(EXIT_FAILURE, "Failed to create output ring\n");
        }
    }

#endif

#if ENABLE_MULTHREAD

    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(pkt_process, mbuf_pool, lcore_id);

#endif

#if ENABLE_UDP_APP
    lcore_id = rte_get_next_lcore(lcore_id, 1, 0);
    rte_eal_remote_launch(udp_server_entry, NULL, lcore_id);

#endif


    while(1){
        //RX
        struct rte_mbuf *rx[BURST_SIZE];
        unsigned num_recvd =  rte_eth_rx_burst(gDpdkPortId, 0, rx, BURST_SIZE);
        if(num_recvd > BURST_SIZE){

            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");

        }else if(num_recvd > 0){
        
            rte_ring_sp_enqueue_burst(ring->in, (void *const *)rx, num_recvd, NULL);
            
        }

        
        //TX
        struct rte_mbuf *tx[BURST_SIZE];
        unsigned nb_tx = rte_ring_sc_dequeue_burst(ring->out, (void **)tx, BURST_SIZE, NULL);
        if(nb_tx >0){
            //printf("main: tx, burst\n");
            int sent = rte_eth_tx_burst(gDpdkPortId, 0, tx, nb_tx);
          
            unsigned i = 0;
            for(i = 0; i<nb_tx ; i++){
                if(ring == NULL){
                rte_pktmbuf_free(tx[i]);
                }
            }
        }

#if ENABLE_TIMER

    static uint64_t prev_tsc = 0, cur_tsc;   
    uint64_t diff_tsc; 

    cur_tsc = rte_rdtsc();
		diff_tsc = cur_tsc - prev_tsc;
		if (diff_tsc > TIMER_RESOLUTION_CYCLES) {
			rte_timer_manage();
			prev_tsc = cur_tsc;  
		}

#endif

    }
}