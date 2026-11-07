#include<stdio.h>

#include<rte_eal.h>
#include<rte_ethdev.h>
#include<rte_mbuf.h>
#include<arpa/inet.h>


#include "arp.h"

#include<rte_timer.h>
#include <rte_cycles.h>
#include <rte_lcore.h>
#include <rte_malloc.h>

#define ENABLE_SEND  1
#define ENABLE_ARP   1
#define ENABLE_ICMP  1
#define ENABLE_DEBUG 1


#define ENABLE_ARP_REPLY 1

#define ENABLE_TIMER     1

#define NUM_BUFF (4096-1)

#define BURST_SIZE 32

#define TIMER_RESOLUTION_CYCLES 60000000000ULL /* around 10s at 2 Ghz */
#if ENABLE_SEND

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



int gDpdkPortId = 0;

static const struct rte_eth_conf port_conf_default = {
    .rxmode = {.max_rx_pkt_len = RTE_ETHER_MAX_LEN}
};



static void ks_init_port(struct rte_mempool* mbuf_pool){
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
    printf("%s%s", name, buf);
}    

#if ENABLE_TIMER

static void arp_request_timer_cb(__attribute__((unused)) struct rte_timer *tim,
	  __attribute__((unused)) void *arg){//timer0_cb

    struct rte_mempool *mbuf_pool = (struct rte_mempool *)arg;

#if 0
    struct rte_mbuf *arpbuf = ka_send_arp(mbuf_pool, ahdr->arp_data.arp_sha.addr_bytes,
        ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

    rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
    rte_pktmbuf_free(txbuf);
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

            print_etheraddr("ARP发送目标MAC:\n", &eth->d_addr);
        }

        rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
        rte_pktmbuf_free(arpbuf);
    }

}

#endif








int main(int argc, char* argv[]){
    
    struct in_addr addr ;

    if(rte_eal_init(argc, argv) < 0){
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_BUFF,
        0, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
    if(mbuf_pool == NULL){
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    ks_init_port(mbuf_pool);

    rte_eth_macaddr_get(gDpdkPortId, (struct rte_ether_addr *)gSrcMac);
    

#if ENABLE_TIMER
    rte_timer_subsystem_init();
    struct rte_timer arp_timer;
    
    rte_timer_init(&arp_timer);

    uint64_t hz = rte_get_timer_hz();
    unsigned lcore_id = rte_lcore_id();

	rte_timer_reset(&arp_timer, hz, PERIODICAL, lcore_id, arp_request_timer_cb, mbuf_pool);

#endif


    while(1){

        struct rte_mbuf *mbufs[BURST_SIZE];
        unsigned num_recvd =  rte_eth_rx_burst(gDpdkPortId, 0, mbufs, BURST_SIZE);
        if(num_recvd > BURST_SIZE){

            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");

        }
    
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

                        //printf("arp --> request");

                        struct rte_mbuf *arpbuf = ka_send_arp(mbuf_pool, RTE_ARP_OP_REPLY,ahdr->arp_data.arp_sha.addr_bytes,
                            ahdr->arp_data.arp_tip, ahdr->arp_data.arp_sip);

                        rte_eth_tx_burst(gDpdkPortId, 0, &arpbuf, 1);
                        rte_pktmbuf_free(arpbuf);   
                        rte_pktmbuf_free(mbufs[i]); 
                    }else if(ahdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REPLY)){

                        //printf("arp --> reply\n");

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
                            print_etheraddr("arp entry --> mac:  ", (struct rte_ether_addr *)iter->hwaddr);
                            
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
                rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
                rte_pktmbuf_free(txbuf);
#endif
                

            }

#if ENABLE_ICMP

            if(iphdr->next_proto_id == IPPROTO_ICMP){
                struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

                //addr.s_addr = iphdr->src_addr;
                //printf("icmp ---> src:%s ",inet_ntoa(addr));

                //addr.s_addr = iphdr->dst_addr;
                //printf("local: %s ,type:%d\n",inet_ntoa(addr),icmphdr->icmp_type);
                
                if(icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST){
                    
                    struct rte_mbuf *txbuf = ka_send_icmp(mbuf_pool, ehdr->s_addr.addr_bytes, iphdr->dst_addr,
                        iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);
                    
                    rte_eth_tx_burst(gDpdkPortId, 0, &txbuf, 1);
                    rte_pktmbuf_free(txbuf);

                    rte_pktmbuf_free(mbufs[i]);
                }

                
            }


#endif

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