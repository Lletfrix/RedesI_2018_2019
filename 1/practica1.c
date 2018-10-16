/***************************************************************************
practica1.c
Muestra el tiempo de llegada de los primeros 50 paquetes a la interface eth0
y los vuelca a traza nueva (�correctamente?) con tiempo actual

 Compila: gcc -Wall -o EjemploPcapP1 EjemploPcapP1.c -lpcap
 Autor: Jose Luis Garcia Dorado - Rafael Sánchez & Sergio Galán
 2018 EPS-UAM
***************************************************************************/

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <stdio.h>
#include <stdlib.h>
#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <inttypes.h>
#include <stdbool.h>
#include <ctype.h>

#include "practica1.h"

#define ERROR 1
#define OK 0
#define NET_INTERFACE "wlp2s0"
#define MINUTES 30
#define SNAPLEN 65535 //Following libpcap man page, this makes every package to be fully saved.
#define ETH_FRAME_MAX 65535    // Tamano maximo trama ethernet
#define BYTE_COL_PRINT 16

pcap_t *descr=NULL,*descr2=NULL;
pcap_dumper_t *pdumper=NULL;
int nbytes = 0;

int main(int argc, char **argv)
{
    int retorno=0,contador=0;
    char errbuf[PCAP_ERRBUF_SIZE];
    char file_name[256];
    struct timeval time;

    if(signal(SIGINT,handle)==SIG_ERR){
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(ERROR);
    }

    if(argc == 2){
        if(!aredigits(argv[1])){
            printf("Error: El argumento debe ser un número entero.\n");
            exit(ERROR);
        }
        //Apertura de interface
       if(!(descr = pcap_open_live(NET_INTERFACE,SNAPLEN,0,100, errbuf))){
            printf("Error: pcap_open_live(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
            exit(ERROR);
        }
        //Para volcado de traza
        descr2=pcap_open_dead(DLT_EN10MB,ETH_FRAME_MAX);
        if (!descr2){
            printf("Error al abrir el dump.\n");
            pcap_close(descr);
            exit(ERROR);
        }
        gettimeofday(&time,NULL);
        sprintf(file_name,"captura."NET_INTERFACE".%lld.pcap",(long long)time.tv_sec);
        pdumper=pcap_dump_open(descr2,file_name);
        if(!pdumper){
            printf("Error al abrir el dumper: %s, %s %d.\n",pcap_geterr(descr2),__FILE__,__LINE__);
            pcap_close(descr);
            pcap_close(descr2);
            exit(ERROR);
        }
    }else if(argc == 3){
        if(!(descr = pcap_open_offline(argv[2], errbuf))){
            printf("Error: pcap_open_offline(): %s, %s %d.\n",errbuf,__FILE__,__LINE__);
            exit(ERROR);
        }
    }else{
        printf("NAME\n");
        printf("\tpractica1 - capture live packages or analyze a given frame.\n");
        printf("SYNOPSYS\n");
        printf("\tpractica1 NBYTES [FFILENAME]\n");
        printf("DESCRIPTION\n");
        printf("\tAnalyze the first NBYTES of given frame FFILENAME. With no FFILENAME, capture live packages from eth0.\n");
        exit(ERROR);
    }
    nbytes = atoi(argv[1]); //TODO: Check this is a number.

    //Se pasa el contador como argumento, pero sera mas comodo y mucho mas habitual usar variables globales
    retorno = pcap_loop (descr,-1,fa_nuevo_paquete, (uint8_t*)&contador);
    if(retorno == -1){         //En caso de error
        printf("Error al capturar un paquete %s, %s %d.\n",pcap_geterr(descr),__FILE__,__LINE__);
        pcap_close(descr);
        pcap_close(descr2);
        pcap_dump_close(pdumper);
        exit(ERROR);
    }
    else if(retorno==-2 && contador <= 0){ //pcap_breakloop() no asegura la no llamada a la funcion de atencion para paquetes ya en el buffer
        printf("Llamada a %s %s %d.\n","pcap_breakloop()",__FILE__,__LINE__);
    }
    else if(retorno == 0){
        printf("No mas paquetes o limite superado %s %d.\n",__FILE__,__LINE__);
    }
    printf("Numero de paquetes capturados: %d\n", contador);

    if(pdumper){
        pcap_dump_close(pdumper);
    }
    if(descr){
        pcap_close(descr);
    }
    if(descr2){
        pcap_close(descr2);
    }

    return OK;
}

bool aredigits(char *s){
    while(*s){
        if(!isdigit(*s)){
            return false;
        }
        s++;
    }
    return true;
}

void print_pkt_hex(const uint32_t caplen, const uint8_t *pkt){
    for (size_t i = 1; i <= nbytes && i<=caplen; i++) {
        printf("%02"PRIx8" ", pkt[i]);
        if(i%BYTE_COL_PRINT==0){
            printf("\n");
        }
    }
}

void handle(int nsignal){
    printf("Control C pulsado\n");
    if(descr)
        pcap_breakloop(descr);
        return;
 }

void fa_nuevo_paquete(uint8_t *usuario, const struct pcap_pkthdr* cabecera, const uint8_t* paquete){
    int* num_paquete=(int *)usuario;
    (*num_paquete)++;
    struct pcap_pkthdr header;
    printf("Nuevo paquete capturado a las %s",ctime((const time_t*)&(cabecera->ts.tv_sec)));
    print_pkt_hex(cabecera->caplen, paquete);
    printf("\n\n");
    if(pdumper){
        header.ts.tv_sec = cabecera->ts.tv_sec + MINUTES*60;
        header.ts.tv_usec = cabecera->ts.tv_usec;
        header.caplen = cabecera->caplen;
        header.len = cabecera->len;
        pcap_dump((uint8_t *)pdumper,&header,paquete);
    }
}
