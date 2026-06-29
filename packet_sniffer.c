#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <unistd.h>
#include <stdarg.h>
#include <time.h>
#include <linux/if_ether.h> 
#include <errno.h>
#include <linux/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <signal.h>
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <pthread.h>

#define MAX_TRACK 1024

pthread_cond_t cond;
pthread_mutex_t lock;

void *parse_packet(char *args, int len);

struct flow_count
{
    char src_ip[16];
    char dst_ip[16];
    uint16_t sport;
    uint16_t dport;
    size_t count;
};

struct flow_count_hash
{
  struct flow_count flow_hash[MAX_TRACK];
  size_t count_hash;
};

struct flow_count_hash flow_count_table;


struct src_ip_count
{
  char src_ip[16];
  size_t count;
};

struct dest_ip_count
{
  char dest_ip[16];
  size_t count;
};

struct dport_count
{
  uint16_t dport;
  size_t count;
};
 
struct src_ip_hash
{
  struct src_ip_count src_ip_hash[MAX_TRACK];
  size_t count_hash;
};

struct dest_ip_hash
{
  struct dest_ip_count dest_ip_hash[MAX_TRACK];
  size_t count_hash;
};

struct dport_hash  
{ 
  struct dport_count dport_hash[MAX_TRACK];
  size_t count_hash;
};

struct src_ip_hash src_ip_table;
struct dest_ip_hash dest_ip_table;
struct dport_hash dport_table;


FILE *fp = NULL;
int server_fd;
char payload_buf[256];
int promisc_enabled= 0;
struct ifreq ifr;
time_t current;
int stats_interval;

#define DEBUG 0

const char *helper = "\n"
"Usage:\n"
  "sudo ./sniffer [filter] [options]\n"
"\n"
"Filters:\n"
  "tcp              Capture only TCP packets\n"
  "udp              Capture only UDP packets\n"
  "arp              Capture only ARP packets\n"
  "icmp              Capture only ICMP packets\n"
  "port <number>    Filter packets by port\n"
"\n"
"Options:\n"
  "--payload-size N     Print first N payload bytes\n"
  "--no-payload         Disable payload printing\n"
  "--stats-interval N   Print statistics every N seconds\n"
  "--promisc            set interface to promiscus mode\n"
  "--help               Show this help message\n";  

size_t Total_packets =  0;
size_t Total_IPv4_packets = 0;
size_t Total_TCP_packets = 0;
size_t Total_UDP_packets = 0;
size_t Total_ARP_packets = 0;
size_t Total_ICMP_packets = 0;
size_t Total_Unknown_packets = 0;
size_t Total_bytes_captured = 0;

size_t Prev_Total_packets =  0;
size_t Prev_Total_IPv4_packets = 0;
size_t Prev_Total_TCP_packets = 0;
size_t Prev_Total_UDP_packets = 0;
size_t Prev_Total_ARP_packets = 0;
size_t Prev_Total_ICMP_packets = 0;
size_t Prev_Total_Unknown_packets = 0;
size_t Prev_Total_bytes_captured = 0;


void logging(char *level, char *msg,...)
{
  time_t now = time(NULL);
  struct tm *t = localtime(&now);
  char buffer[24];
  strftime(buffer, sizeof(buffer),"%Y-%m-%d %H:%M:%S", t);

  fprintf(stderr,"[%s] [%s]: ", buffer, level);
  fprintf(fp,"[%s] [%s]: ", buffer, level);
  va_list args,args1;
   va_start(args, msg);
   va_copy(args1,args);
   vfprintf(stderr,msg,args);
   vfprintf(fp,msg,args1);
   va_end(args);
   va_end(args1);
   fprintf(stderr, "\n");
   fprintf(fp, "\n");
   fflush(fp);

   return;
}


void cleanup_and_exit()
{
  if(promisc_enabled == 1)
    {
      ifr.ifr_flags &= ~IFF_PROMISC;
      if(ioctl(server_fd, SIOCSIFFLAGS, &ifr) < 0)
	{
	   logging("ERROR",
            "Failed to disable promiscuous mode: %s",
            strerror(errno));
	}
    }
  if(fp != NULL)
    {
      fclose(fp);
    }
  if(server_fd >= 0)
    {
      close(server_fd);
    }
    exit(0);
}

int no_filter(int argc, char *argv[])
{
  return (argc < 2) || (argc >= 2 && strstr(argv[1],"--") != NULL);
}


int get_option_filter(int argc , char *argv[], char *option, char *value, int value_size)
{
  if(argc >= 2)
  {
    for(int i = 1; i < argc ; i++)
      {
        if(strcmp(argv[i],option) == 0)
        {
            if(i+1 < argc && argv[i+1] != NULL )
            {
              snprintf(value,value_size,"%s",argv[i+1]);
            }
         
          return 1;
        }
      }
  }
  return 0;
}

int has_option_filter(int argc , char *argv[], char *option)
{ 
  if(argc >= 2)
  {
    for(int i = 1; i < argc ; i++)
      {
	if(strcmp(argv[i],option) == 0)
	{
	  	  
	  return 1;
	}
      }
  }
  return 0;
}

int protocol_filter(int argc, char *args[], char *protocol)
{
  if(argc >= 2 )
    if(strcmp(args[1],protocol) == 0 )
      return 1;
  return 0;
}

int port_filter(int argc, char *args[], uint16_t srcport, uint16_t dstport)
{
  if(argc == 3 && args[2] != NULL && (strcmp(args[1],"port") == 0))
    {
       uint16_t port =  atoi(args[2]);
       if(srcport == port || dstport == port)
           return 1;
       return 0;
    }

  return 0;
}


void print_payload_hex(unsigned char *ptr, uint32_t payloadlen , int N)
{

  logging("INFO","Payload Length is %u", payloadlen);

  memset(payload_buf,0,sizeof(payload_buf));
  
    for(uint16_t i = 0; i < payloadlen && i < N ; i++)
    {
      snprintf(payload_buf+strlen(payload_buf),sizeof(payload_buf)-strlen(payload_buf),"%02X ",ptr[i]);
    }

  logging("INFO","PAYLOAD : %s", payload_buf);

  return;
}

const char * detect_app_protocol(uint16_t sport, uint16_t dport)
{
      if(sport == 80 || dport == 80)
           return "HTTP";
      else if(sport == 443 || dport == 443)
           return "HTTPS/TLS";
      else if(sport == 53 || dport == 53)
           return "DNS";
      else if(sport == 67 || dport == 67 || sport == 68 || dport == 68)
           return "DHCP";
      return "";
}
void payload_print(unsigned char *ptr, uint32_t payloadlen,char *app_proto,int argc, char *argv[], char *value,int value_size)
{
  uint16_t N = 64;

  if(has_option_filter(argc, argv, "--payload-size"))
    {
      get_option_filter(argc, argv, "--payload-size",value,value_size);
      
      N = atoi(value);

      N = (N > 64 ) ? 64 : N; 
    }
  
  if(payloadlen == 0)
    {
      logging("INFO","Payload Length is %u", payloadlen);
      return;
    }
    
  print_payload_hex(ptr,payloadlen,N);
  
  uint32_t i = 0;
  
  if(strcmp(app_proto,"HTTP") == 0 || strcmp(app_proto,"HTTPS/TLS")==0)
    {
        memset(payload_buf,0,sizeof(payload_buf));
        
	while( i < payloadlen && ptr[i] != '\r')
	{
	  snprintf(payload_buf+strlen(payload_buf),sizeof(payload_buf)-strlen(payload_buf),"%c",ptr[i]);
	  i++;
	}
	logging("INFO","PAYLOAD : %s", payload_buf);
    }
  
  return;
}

void print_statistics()
{    
     logging("INFO", "********************statistics*****************");
     logging("INFO", "Total_packets : %zu", Total_packets);
     logging("INFO", "Total_IPv4_packets : %zu", Total_IPv4_packets);
     logging("INFO", "Total_TCP_packets : %zu", Total_TCP_packets);
     logging("INFO", "Total_UDP_packets : %zu", Total_UDP_packets);
     logging("INFO", "Total_ARP_packets : %zu", Total_ARP_packets);
     logging("INFO", "Total_ICMP_packets : %zu", Total_ICMP_packets);
     logging("INFO", "Total_Unknown_packets : %zu", Total_Unknown_packets);
     logging("INFO", "Total_bytes_captured : %zu", Total_bytes_captured);
     logging("INFO", "***********************************************");
     
     return;
}



void handler_function(int sig)
{
  logging("INFO", "sig: %d",sig);   
  print_statistics();
  cleanup_and_exit();
   return;
  
}


void parse_ethernet(struct ethhdr *eh)
{
  logging("INFO", "************ETHERNET FRAME INFO*****************");            
  logging("INFO", "Destination MAC : %02X:%02X:%02X:%02X:%02X:%02X",eh->h_dest[0],eh->h_dest[1],eh->h_dest[2],eh->h_dest[3],eh->h\
_dest[4],eh->h_dest[5]);                                                                                                               
  logging("INFO", "SOURCE MAC : %02X:%02X:%02X:%02X:%02X:%02X",eh->h_source[0],eh->h_source[1],eh->h_source[2],eh->h_source[3],eh\
->h_source[4],eh->h_source[5]);                                                                                                        
  unsigned short proto = ntohs(eh->h_proto);

  if(proto == ETH_P_IP)                                                                                                           
       logging("INFO","Protocol : IPv4");                                                                                            
  else if(proto == ETH_P_ARP)                                                                                                     
       logging("INFO","Protocol : ARP");                                                                                             
  else if(proto == ETH_P_IPV6)                                                                                                    
       logging("INFO","Protocol : IPv6");                                                                                            
  else                                                                                                                            
       logging("INFO","Protocol : %d",proto);
}
void parse_ipv4(struct iphdr *ih)
{
       logging("INFO", "************IPV4 PACKET INFO*****************");
       uint32_t svalue = ntohl(ih->saddr);                                                        
       logging("INFO", "Source IP : %u.%u.%u.%u",(svalue >> 24) & 0XFF , (svalue >> 16) & 0XFF, (\
svalue >> 8) & 0XFF , svalue & 0XFF);                                                             
       uint32_t dvalue = ntohl(ih->daddr);                                                        
       logging("INFO", "Destination IP : %u.%u.%u.%u",(dvalue >> 24) & 0XFF , (dvalue >> 16) & 0X\
FF, (dvalue >> 8) & 0XFF , dvalue & 0XFF);                                                        
                                                                                                  
       if(ih->protocol == IPPROTO_TCP)                                                            
         logging("INFO", "Protocol : TCP");                                                       
       else if(ih->protocol == IPPROTO_UDP)                                                       
         logging("INFO", "Protocol : UDP");                                                         
       logging("INFO", "TTL : %u", ih->ttl);                                                      
       logging("INFO", "IP Length : %u", ntohs(ih->tot_len));                                     
      
  return;
}

void handle_arp_packet(struct ethhdr *eh, int argc, char *argv[], int bytes_read)
{
  logging("INFO", "************ARP PACKET INFO*****************");
   unsigned short proto = ntohs(eh->h_proto);
   if(proto == ETH_P_ARP)
    {
      
     Total_ARP_packets++;
     
     if( no_filter(argc,argv) || protocol_filter(argc, argv,"arp"))
     {
       logging("INFO","ARP packet LEN=%zd", bytes_read);
      }
     }
   return;
}
void handle_tcp_packet(struct tcphdr *tp, uint16_t sport, uint16_t dport)
{
  
   logging("INFO", "************TCP PACKET INFO*****************");                                                                                                                                   
   logging("INFO","SOURCE PORT is %u", sport);                                                                                    
   logging("INFO","DESTINATION PORT is %u", dport);                                                                               
   logging("INFO","SEQUENCE NUMBER IS is %u", ntohl(tp->seq));                                                                    
   logging("INFO","ACKNOWLEDGEMENT NUMBER is is %u", ntohl(tp->ack_seq));                                                         
   logging("INFO","TCP header length is %u bytes", tp->doff * 4);                                                                 
   logging("INFO","SYN flag is is %u", tp->syn);                                                                                  
   logging("INFO","ACK flag is is %u", tp->ack);                                                                                  
   logging("INFO","FIN flag is is %u", tp->fin);                                                                                  
   logging("INFO","RST flag is is %u", tp->rst);                                                                                  
      
  return;
}
void handle_udp_packet(struct udphdr *up,uint16_t sport, uint16_t dport)
{
   logging("INFO", "************UDP PACKET INFO*****************");                                                                                                                              
   logging("INFO","SOURCE PORT is %u", sport);                                                                                    
   logging("INFO","DESTINATION PORT is %u", dport);                                                                               
   logging("INFO","UDP length is %u", ntohs(up->len));                                                                            
   logging("INFO","checksum length is %04X", ntohs(up->check));                                                                   
   
  return;
}

char * parse_icmp(struct icmphdr *icp, char *msg)
{
  
  if(icp->type == 0)
    {
      if(icp->code == 0)
	strcpy(msg,"Echo Reply");
    }
  else if(icp->type == 3)
    {
      if(icp->code == 0)
	strcpy(msg,"Network unreachable");
      else if(icp->code == 1)
	strcpy(msg,"Host unreachable");
      else if(icp->code == 2)
	strcpy(msg,"Protocol unreachable");
      else if(icp->code == 3)
        strcpy(msg,"Port unreachable");
    }
  else if(icp->type == 8)
    {
      if(icp->code == 0)
	strcpy(msg,"Echo Request");
    }
  else if(icp->type == 11)
    {
      if(icp->code == 0)
	strcpy(msg,"TTL expired in transit");
    }
  else
    strcpy(msg,"unknown icmp type");
  #if DEBUG
  logging("INFO", "************ICMP PACKET INFO*****************");
  logging("INFO", "ICMP Type is :%d", icp->type);
  logging("INFO", "ICMP code is :%d", icp->code);
  logging("INFO", "ICMP protocol message is :%s", msg);
  logging("INFO", "ICMP checksum is :%04X", ntohs(icp->checksum));
  logging("INFO", "ICMP session id is :%u", ntohs(icp->un.echo.id));
  logging("INFO", "ICMP sequence number is :%u", ntohs(icp->un.echo.sequence));
  #endif
  
  return msg;
  }

void print_traffic_rate()
{
   
  logging("INFO", "*************TRAFFIC RATE***************");
  logging("INFO", "Total_packets/sec : %zu", Total_packets-Prev_Total_packets);
  logging("INFO", "Total_IPv4_packets/sec : %zu", Total_IPv4_packets-Prev_Total_IPv4_packets);
  logging("INFO", "Total_TCP_packets/sec : %zu", Total_TCP_packets-Prev_Total_TCP_packets);
  logging("INFO", "Total_UDP_packets/sec : %zu", Total_UDP_packets-Prev_Total_UDP_packets);
  logging("INFO", "Total_ARP_packets/sec : %zu", Total_ARP_packets-Prev_Total_ARP_packets);
  logging("INFO", "Total_ICMP_packets/sec : %zu", Total_ICMP_packets-Prev_Total_ICMP_packets);
  logging("INFO", "Total_Unknown_packets/sec : %zu", Total_Unknown_packets-Prev_Total_Unknown_packets);
  logging("INFO", "Total_bytes_captured/sec : %zu", Total_bytes_captured-Prev_Total_bytes_captured);
  logging("INFO", "***********************************************");

   
   Prev_Total_packets = Total_packets;
   Prev_Total_IPv4_packets = Total_IPv4_packets;
   Prev_Total_TCP_packets = Total_TCP_packets;
   Prev_Total_UDP_packets = Total_UDP_packets;
   Prev_Total_ARP_packets = Total_ARP_packets;
   Prev_Total_ICMP_packets = Total_ICMP_packets;
   Prev_Total_Unknown_packets = Total_Unknown_packets;
   Prev_Total_bytes_captured = Total_bytes_captured;
   
   return;
}

void print_top_talkers()
{
  size_t max_count = 0;
  char max_srcip[16];
  max_srcip[0]= '\0';
  char max_destip[16];
  max_destip[0] = '\0';
  uint16_t max_dport;
  max_dport = 0;
  
        for(size_t i = 0; i < src_ip_table.count_hash ; i++ )
        {
          if(src_ip_table.src_ip_hash[i].count > max_count)
	  {
	    snprintf(max_srcip, 16,"%s", src_ip_table.src_ip_hash[i].src_ip);
            max_count = src_ip_table.src_ip_hash[i].count;
          }
        }

	
	max_count = 0;

	for(size_t i = 0; i < dest_ip_table.count_hash ; i++ )
        {
          if(dest_ip_table.dest_ip_hash[i].count > max_count)
            {
              snprintf(max_destip, 16,"%s", dest_ip_table.dest_ip_hash[i].dest_ip);

              max_count = dest_ip_table.dest_ip_hash[i].count;
            }

        }
	
	
	max_count = 0;
	for(size_t i = 0; i < dport_table.count_hash ; i++ )
        {
	  if(dport_table.dport_hash[i].count > max_count)
            {

	      max_dport = dport_table.dport_hash[i].dport;
	      max_count = dport_table.dport_hash[i].count; 
            }
        }
	logging("INFO","***************TOP TALKERS*************");
        logging("INFO","TOP SOURCE IP ADDRESS IS: %s", max_srcip);
        logging("INFO","TOP DESTINATION IP ADDRESS IS: %s", max_destip);
	logging("INFO","TOP PORT NUMBER IS: %u", max_dport);
	logging("INFO","****************************************");

	return;
	
}


void update_top_talkers(char *src_ip, char *dest_ip, uint16_t dport)
{
  int found = 0;
  
  if(src_ip_table.count_hash < MAX_TRACK)
    {
      for(size_t i = 0; i < src_ip_table.count_hash ; i++ )
	{
	  if(strcmp(src_ip_table.src_ip_hash[i].src_ip, src_ip)==0)
	  {
	    src_ip_table.src_ip_hash[i].count++;

	    found = 1;
	    
	    break;
	  }
	}
         if(!found )
	  {
	    snprintf(src_ip_table.src_ip_hash[src_ip_table.count_hash].src_ip, 16,"%s",src_ip);
	    src_ip_table.src_ip_hash[src_ip_table.count_hash].count++;
	    src_ip_table.count_hash++;
	  }
	
    }

  found = 0;

  if(dest_ip_table.count_hash < MAX_TRACK)
    {
      for(size_t i = 0; i < dest_ip_table.count_hash ; i++ )
	{
	  if(strcmp(dest_ip_table.dest_ip_hash[i].dest_ip,dest_ip)== 0)
	    {
	      dest_ip_table.dest_ip_hash[i].count++;

	      found = 1;
	      break;
	    }
	}
	
      if(!found)
	{
	  snprintf(dest_ip_table.dest_ip_hash[dest_ip_table.count_hash].dest_ip,16,"%s", dest_ip);
	  dest_ip_table.dest_ip_hash[dest_ip_table.count_hash].count++;
	  dest_ip_table.count_hash++;
	}
      
    }
  found = 0;
  if(dport_table.count_hash < MAX_TRACK)
    {
      for(size_t i = 0; i < dport_table.count_hash ; i++ )
	{
	  if(dport_table.dport_hash[i].dport==dport)
	    {
	      found =1 ;
	      dport_table.dport_hash[i].count++;
	      break;
	    }
	}	
      if(!found)
	{
	  dport_table.dport_hash[dport_table.count_hash].dport=dport;
          dport_table.dport_hash[dport_table.count_hash].count++;
	  dport_table.count_hash++;
	}
      
    }
  return;
}

void update_flow_count(char *srcip, char *destip, uint16_t sport , uint16_t dport)
{
  size_t i;

  if(flow_count_table.count_hash >= MAX_TRACK)
    return;
  
  for( i = 0 ; i < flow_count_table.count_hash ; i++)
    {
      if(strcmp(flow_count_table.flow_hash[i].src_ip,srcip) == 0 && strcmp(flow_count_table.flow_hash[i].dst_ip,destip) == 0 && flow_count_table.flow_hash[i].sport == sport && flow_count_table.flow_hash[i].dport == dport )
	{
	  flow_count_table.flow_hash[i].count++;
	  
	  break;
	}
    }
  if(i == flow_count_table.count_hash)
    {
      snprintf(flow_count_table.flow_hash[i].src_ip,16,"%s",srcip);
      snprintf(flow_count_table.flow_hash[i].dst_ip,16,"%s",destip);
      flow_count_table.flow_hash[i].sport = sport;
      flow_count_table.flow_hash[i].dport = dport;
      flow_count_table.flow_hash[i].count++;
      flow_count_table.count_hash++;
    }
  return;
}

void print_flow_count()
{
   
  for(size_t i = 0 ; i < flow_count_table.count_hash ; i++)
    {
      logging("INFO","%s:%u -> %s:%u packets=%zu", flow_count_table.flow_hash[i].src_ip ,flow_count_table.flow_hash[i].sport,flow_count_table.flow_hash[i].dst_ip ,flow_count_table.flow_hash[i].dport,flow_count_table.flow_hash[i].count);
    }
    return;
}


struct packet_item
{

  char packet[65535];
  size_t len;
};

struct packet_queue
{
  struct packet_item *items;
  int head;
  int tail;
  int count;
  int capacity;
  pthread_t t[5];
};

struct workerargs
{
  int argc1;
  char **argv1;  
};

struct packet_queue *queue1;
struct workerargs *arg;

void *capture_thread()
{
    
    char buffer[65535];
    while(1)
    {
       
       memset(buffer,0,sizeof(buffer));
       ssize_t bytes_read = recv(server_fd, buffer, sizeof(buffer), 0);
       if(bytes_read < 0)
         {
           logging("INFO", strerror(errno));
           continue;
         }
       
       pthread_mutex_lock(&lock);
       int index = queue1->head;
       memcpy(queue1->items[index].packet, buffer, bytes_read);
       queue1->items[index].len = bytes_read;
       queue1->head = (queue1->head+1)%queue1->capacity;
       queue1->count++;
       pthread_cond_signal(&cond);
       pthread_mutex_unlock(&lock);
    }
    return NULL;
}

void *worker_thread()
{
    while(1)
    {
       pthread_mutex_lock(&lock);
       while(queue1->count == 0)
       {
	 pthread_cond_wait(&cond, &lock);
       }
       int index = (queue1->tail) % queue1->capacity;
       queue1->tail = (queue1->tail+1) % queue1->capacity;
       char buffer[65535];
       int len;
       memset(buffer,0,sizeof(buffer));
       memcpy(buffer,queue1->items[index].packet, queue1->items[index].len);
       len = queue1->items[index].len;
       queue1->count--;
       pthread_mutex_unlock(&lock);
       parse_packet(buffer,len);
       
    }
    return NULL;
}

void *parse_packet(char *args, int bytes_read)
{
  char buffer[65535];
  memset(buffer,0,sizeof(buffer));
  memcpy(buffer,(char *)args,bytes_read);
  //buffer[bytes_read]= '\0';
  
  char value[64];
  int value_size = 64;
  value[0] = '\0';
  char protocol[16];
  protocol[0] = '\0';
  unsigned char *ptr;
  char app_proto[32];
  app_proto[0] = '\0';
  

  
  
      app_proto[0]= '\0';

      
       Total_packets++;
       pthread_mutex_lock(&lock);
       Total_bytes_captured += bytes_read;
       pthread_mutex_unlock(&lock);
	
       

       if((current-time(NULL)) >= stats_interval )
        {
          current = time(NULL);

	  print_statistics();
	  print_top_talkers();
	  print_flow_count();
        }

       if(current-time(NULL) >= 1)
       {
	 current = time(NULL);
	 print_traffic_rate();
       }

        
        struct ethhdr *eh = (struct ethhdr *)buffer;
	#if DEBUG
	   parse_ethernet(eh);
	#endif
        unsigned short proto = ntohs(eh->h_proto);

	
       if(proto == ETH_P_ARP)
       {
         handle_arp_packet(eh,arg->argc1,arg->argv1,bytes_read);
	 return NULL;
       }
       if(proto != ETH_P_IP &&  proto != ETH_P_ARP)
       {
	 
	   Total_Unknown_packets++;
	 
	  
	   return NULL;
	 
       }
       
       Total_IPv4_packets++;
       

       struct iphdr *ih = (struct iphdr *)(buffer+sizeof(struct ethhdr));
       #if DEBUG
           parse_ipv4(ih);
       #endif

       char src_ip[INET_ADDRSTRLEN];
       char dst_ip[INET_ADDRSTRLEN];
       
       inet_ntop(AF_INET, &ih->saddr, src_ip, sizeof(src_ip));
       inet_ntop(AF_INET, &ih->daddr, dst_ip, sizeof(dst_ip));
       
       
       
       uint16_t ip_header_len = ih->ihl*4;
       
       if(ih->protocol == IPPROTO_TCP)
       {
	  
	 Total_TCP_packets++;
	  
         strcpy(protocol,"TCP");

	
	 struct tcphdr *tp = (struct tcphdr *)(buffer+sizeof(struct ethhdr)+ip_header_len);
	 
	 uint16_t sport = ntohs(tp->source);
	 uint16_t dport = ntohs(tp->dest);

	 update_top_talkers(src_ip, dst_ip,dport);
         update_flow_count(src_ip, dst_ip,sport,dport);
	 
	 strcpy(app_proto,detect_app_protocol(sport,dport));

	 if(no_filter(arg->argc1,arg->argv1) || protocol_filter(arg->argc1,arg->argv1,"tcp") || port_filter(arg->argc1,arg->argv1, sport, dport))
	 {
	   if(*app_proto)
	     {
	       logging("INFO","%s %s %s:%u -> %s:%u LEN=%zd SYN=%d ACK=%d",app_proto, protocol,src_ip,sport,dst_ip,dport,bytes_read,tp->syn,tp->ack);
	     }
	   else
	     {
	       logging("INFO","%s %s:%u -> %s:%u LEN=%zd SYN=%d ACK=%d", prot\
ocol,src_ip,sport,dst_ip,dport,bytes_read,tp->syn,tp->ack);
	     }
	   if(!has_option_filter(arg->argc1, arg->argv1, "--no-payload"))
	    {
	      uint16_t tcp_header_len = tp->doff*4;
	      ptr = (unsigned char *)(buffer+sizeof(struct ethhdr)+ip_header_len+tcp_header_len);
	      int tcp_payload_len = ntohs(ih->tot_len)-ip_header_len-tcp_header_len;
	      payload_print(ptr,tcp_payload_len,app_proto,arg->argc1,arg->argv1,value,value_size);
            }
	 }
         #if DEBUG
         handle_tcp_packet(tp,sport,dport);	 	    
         #endif
       }
       else if(ih->protocol == IPPROTO_UDP)
       {
	  
	 Total_UDP_packets++;
	  
	 strcpy(protocol,"UDP");
	 


         struct udphdr *up = (struct udphdr *)(buffer+sizeof(struct ethhdr)+ip_header_len);
	 uint16_t sport =	ntohs(up->source);
         uint16_t dport =	ntohs(up->dest);

	 update_top_talkers(src_ip, dst_ip,dport);
	 update_flow_count(src_ip, dst_ip,sport,dport);

	 strcpy(app_proto,detect_app_protocol(sport,dport));
	 	 	    
	 if(no_filter(arg->argc1,arg->argv1) || protocol_filter(arg->argc1,arg->argv1,"udp") || port_filter(arg->argc1,arg->argv1, sport, dport))
	   {
	     if(*app_proto)
	       {
		 logging("INFO","%s %s %s:%u -> %s:%u LEN=%zd ",app_proto, protocol,src_ip,sport,dst_ip,dport,bytes_read);
	       }
	     else
	       {
		 logging("INFO", "%s %s:%u -> %s:%u LEN=%zd ", protocol,src_ip\
,sport,dst_ip,dport,bytes_read);
	       }
             if(!has_option_filter(arg->argc1,arg->argv1, "--no-payload"))
	       {
	         ptr = (unsigned char *)(buffer+sizeof(struct ethhdr)+ip_header_len+8);
		 uint16_t udp_payload_len = ntohs(ih->tot_len)-ip_header_len-8;
		 payload_print(ptr,udp_payload_len,app_proto,arg->argc1,arg->argv1, value, value_size);
	       }
	   }
         #if DEBUG
	 handle_udp_packet(up,sport,dport);	  
	 #endif
       }
       else if(ih->protocol == IPPROTO_ICMP)
       {
	 
	 Total_ICMP_packets++;
	 
	 struct icmphdr *icp = (struct icmphdr *)(buffer+sizeof(struct ethhdr )+ip_header_len);
         char msg[50];
	 msg[0]='\0';
	 parse_icmp(icp,msg);

	 update_top_talkers(src_ip, dst_ip, 0);

	 if(no_filter(arg->argc1,arg->argv1) || protocol_filter(arg->argc1,arg->argv1,"icmp"))
	   {
	     logging("INFO", "%s %s -> %s TYPE=%u CODE=%u %s ID=%u SEQ=%u","ICMP",src_ip,dst_ip,icp->type, icp->code,msg,ntohs(icp->un.echo.id),ntohs(icp->un.echo.sequence)); 
	   }
	 
       }
       else
       {
	  
	 Total_Unknown_packets++;
	  
	 return NULL;
       }

  return NULL;  
}
  
int main(int argc , char *argv[])
{
  current = time(NULL);
  signal(SIGINT,handler_function);
  pthread_mutex_init(&lock, NULL);
  char value[64];
  int value_size = 64;
  value[0] = '\0';
  
  queue1 = malloc(sizeof(struct packet_queue));
  queue1->count = 0;
  queue1->head = 0;
  queue1->tail = 0;
  queue1->capacity = 1000;
  queue1->items = (struct packet_item *)malloc(sizeof(struct packet_item)*(queue1->capacity));
  
  if(has_option_filter(argc, argv, "--help"))
  {
    fprintf(stderr,"%s", helper);
    return 0;
  }
  fp = fopen("packets.log","a+");
  
  if(fp == NULL)
  {
      return -1;
  }
  
  memset(&flow_count_table,0,sizeof(flow_count_table));
  memset(&src_ip_table,0, sizeof(src_ip_table));
  memset(&dest_ip_table,0, sizeof(dest_ip_table));
  memset(&dport_table,0, sizeof(dport_table));

  arg = malloc(sizeof(struct workerargs));
  
  arg->argc1 = argc;

  arg->argv1 = (char **)malloc(argc*sizeof(char *));
    
  for(int i=0; i<argc; i++)
  {
    arg->argv1[i] = argv[i];
  }

  if(has_option_filter(arg->argc1, arg->argv1, "--stats-interval"))
  {
    get_option_filter(arg->argc1, arg->argv1, "--stats-interval", value, value_size);
    stats_interval = atoi(value);
  }

  if(has_option_filter(arg->argc1, arg->argv1, "--interface"))
  {
    get_option_filter(arg->argc1, arg->argv1, "--interface", value, value_size);
    memset(&ifr, 0, sizeof(ifr));
    snprintf(ifr.ifr_name, sizeof(ifr.ifr_name),"%s",value);

    if(setsockopt(server_fd,SOL_SOCKET,SO_BINDTODEVICE, &ifr, sizeof(ifr)) < 0)
    {
      logging("ERROR", strerror(errno));
      cleanup_and_exit();
    }
    logging("INFO","Bound sniffer to interface %s",value);

    if(has_option_filter(arg->argc1, arg->argv1, "--promisc"))
    {
      if(ioctl(server_fd,SIOCGIFFLAGS, &ifr) < 0)
      {
         cleanup_and_exit();
      }

      ifr.ifr_flags |= IFF_PROMISC;

      if(ioctl(server_fd,SIOCSIFFLAGS, &ifr) < 0)
      {
         ifr.ifr_flags &= ~IFF_PROMISC;

         cleanup_and_exit();
      }
      logging("INFO","sniffer interface %s is set to promiscous mode",value);
      promisc_enabled = 1;
     }
    }



  pthread_create(&queue1->t[0], NULL, capture_thread, NULL);
  
  for(int i=1 ; i<5; i++)
  {
    pthread_create(&queue1->t[i], NULL, worker_thread, arg);
  }

  pthread_join(queue1->t[0], NULL);

  for(int i=1 ; i<5; i++)
  {
    pthread_join(queue1->t[i], NULL);
  }

  cleanup_and_exit();
  return 0;
}
