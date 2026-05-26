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

FILE *fp = NULL;
int server_fd;
char payload_buf[256];

#define DEBUG 0

const char *helper = "\n"
"Usage:\n"
  "sudo ./sniffer [filter] [options]\n"
"\n"
"Filters:\n"
  "tcp              Capture only TCP packets\n"
  "udp              Capture only UDP packets\n"
  "arp              Capture only ARP packets\n"
  "port <number>    Filter packets by port\n"
"\n"
"Options:\n"
  "--payload-size N     Print first N payload bytes\n"
  "--no-payload         Disable payload printing\n"
  "--stats-interval N   Print statistics every N seconds\n"
  "--help               Show this help message\n";  

size_t Total_packets =  0;
size_t Total_IPv4_packets = 0;
size_t Total_TCP_packets = 0;
size_t Total_UDP_packets = 0;
size_t Total_ARP_packets = 0;
size_t Total_Unknown_packets = 0;
size_t Total_bytes_captured = 0;


void cleanup_and_exit()
{
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

int option_filter(int argc , char *argv[], char *option, int *value)
{
  *value = 0;
  
  if(argc >= 2)
  {
    for(int i = 1; i < argc ; i++)
      {
	if(strcmp(argv[i],option) == 0)
	{
	  if(i+1 < argc && argv[i+1] != NULL )
	    {
	      *value = atoi(argv[i+1]);
	    }
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
void payload_print(unsigned char *ptr, uint32_t payloadlen,char *app_proto,int argc, char *argv[], int *value)
{
  uint16_t N = 64;

  if(option_filter(argc, argv, "--payload-size",value))
    {
      N = *value; 
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
     logging("INFO", "Total_Unknown_packets : %zu", Total_Unknown_packets);
     logging("INFO", "Total_bytes_captured : %zu", Total_bytes_captured);
     logging("INFO", "***********************************************");
     return;
}

void handler_function(int sig)
{
   
  print_statistics();
  cleanup_and_exit();
   return;
  
}


void parse_ethernet(struct ethhdr *eh)
{
              
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
                                                                                                                                 
   logging("INFO","SOURCE PORT is %u", sport);                                                                                    
   logging("INFO","DESTINATION PORT is %u", dport);                                                                               
   logging("INFO","UDP length is %u", ntohs(up->len));                                                                            
   logging("INFO","checksum length is %04X", ntohs(up->check));                                                                   
   
  return;
}
int main(int argc , char *argv[])
{
  signal(SIGINT,handler_function);
  int value = 0;
  
  if(option_filter(argc, argv, "--help", &value))
  {
    fprintf(stderr,"%s", helper);
    return 0;
  }
  fp = fopen("packets.log","a+");
  if(fp == NULL)
    {
      return -1;
    }
 
  char buffer[65536];
  char protocol[10];
  protocol[0] = '\0';
  unsigned char *ptr;
  char app_proto[32];
  app_proto[0] = '\0';
  int stats_interval = 10;

  if(option_filter(argc, argv, "--stats-interval", &value))
    {
      stats_interval = value;   
    }
  
  
  server_fd =  socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if(server_fd < 0)
    {
      logging("INFO",strerror(errno));
      return -1;
    }
  logging("INFO","SERVER socket is created successfully");

  time_t now = time(NULL);

  while(1)
    {
       
       ssize_t bytes_read = recv(server_fd, buffer, sizeof(buffer), 0);
       if(bytes_read < 0)
	 {
       	   logging("INFO", strerror(errno));
	   continue;
	 }
       app_proto[0]= '\0';
       Total_packets++;
       Total_bytes_captured += bytes_read;

       if((time(NULL)-now) >= stats_interval )
        {
          now = time(NULL);

	  print_statistics();
        }

        
        struct ethhdr *eh = (struct ethhdr *)buffer;
	#if DEBUG
	   parse_ethernet(eh);
	#endif
        unsigned short proto = ntohs(eh->h_proto);

	
       if(proto == ETH_P_ARP)
       {
         handle_arp_packet(eh,argc,argv,bytes_read);
	 continue;
       }
       if(proto != ETH_P_IP &&  proto != ETH_P_ARP)
       {
	   Total_Unknown_packets++;
	   continue;
	 
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

       
       if(ih->protocol == IPPROTO_TCP)
       {
	 Total_TCP_packets++;
         strcpy(protocol,"TCP");
	 uint16_t ip_header_len = ih->ihl*4;
	
	 struct tcphdr *tp = (struct tcphdr *)(buffer+sizeof(struct ethhdr)+ip_header_len);
	 
	 uint16_t sport = ntohs(tp->source);
	 uint16_t dport = ntohs(tp->dest);
	 
	 strcpy(app_proto,detect_app_protocol(sport,dport));

	 if(no_filter(argc,argv) || protocol_filter(argc,argv,"tcp") || port_filter(argc,argv, sport, dport))
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
	   if(!option_filter(argc, argv, "--no-payload", &value))
	    {
	      uint16_t tcp_header_len = tp->doff*4;
	      ptr = (unsigned char *)(buffer+sizeof(struct ethhdr)+ip_header_len+tcp_header_len);
	      int tcp_payload_len = ntohs(ih->tot_len)-ip_header_len-tcp_header_len;
	      payload_print(ptr,tcp_payload_len,app_proto,argc,argv,&value);
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
	 

	 int ip_header_len = ih->ihl*4;
         struct udphdr *up = (struct udphdr *)(buffer+sizeof(struct ethhdr)+ip_header_len);
	 uint16_t sport =	ntohs(up->source);
         uint16_t dport =	ntohs(up->dest);

	 strcpy(app_proto,detect_app_protocol(sport,dport));
	 	 	    
	 if(no_filter(argc,argv) || protocol_filter(argc,argv,"udp") || port_filter(argc,argv, sport, dport))
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
             if(!option_filter(argc, argv, "--no-payload", &value))
	       {
	         ptr = (unsigned char *)(buffer+sizeof(struct ethhdr)+ip_header_len+8);
		 uint16_t udp_payload_len = ntohs(ih->tot_len)-ip_header_len-8;
		 payload_print(ptr,udp_payload_len,app_proto,argc,argv, &value);
	       }
	   }
         #if DEBUG
	 handle_udp_packet(up,sport,dport);	  
	 #endif
       }
       else
       {
	 Total_Unknown_packets++;
	 continue;
       }
    }
  cleanup_and_exit();
  return 0;
}
