/***************************************************************************
 practica2.c
 Muestra las direciones Ethernet de la traza que se pasa como primer parametro.
 Debe complatarse con mas campos de niveles 2, 3, y 4 tal como se pida en el enunciado.
 Debe tener capacidad de dejar de analizar paquetes de acuerdo a un filtro.

 Compila: gcc -Wall -o practica2 practica2.c -lpcap, make
 Autor: Jose Luis Garcia Dorado, Jorge E. Lopez de Vergara Mendez, Rafael Leira, Javier Ramos
 2018 EPS-UAM
***************************************************************************/

#include <stdio.h>
#include <stdlib.h>

#include <pcap.h>
#include <string.h>
#include <netinet/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <signal.h>
#include <time.h>
#include <getopt.h>
#include <inttypes.h>
#include <stdbool.h>

#include "practica2.h"

/*Definicion de constantes *************************************************/
#define ETH_ALEN      6      /* Tamanio de la direccion ethernet           */
#define ETH_HLEN      14     /* Tamanio de la cabecera ethernet            */
#define ETH_TLEN      2      /* Tamanio del campo tipo ethernet            */
#define ETH_FRAME_MAX 1514   /* Tamanio maximo la trama ethernet (sin CRC) */
#define ETH_FRAME_MIN 60     /* Tamanio minimo la trama ethernet (sin CRC) */
#define ETH_DATA_MAX  (ETH_FRAME_MAX - ETH_HLEN) /* Tamano maximo y minimo de los datos de una trama ethernet*/
#define ETH_DATA_MIN  (ETH_FRAME_MIN - ETH_HLEN)
#define IP_ALEN 4            /* Tamanio de la direccion IP                    */
#define OK 0
#define ERROR 1
#define PACK_READ 1
#define PACK_ERR -1
#define BREAKLOOP -2
#define NO_FILTER 0
#define NO_LIMIT -1
#define SNAPLEN 65535 //Following libpcap man page, this makes every package to be fully saved.
#define IP_INIT 2
#define IP_TLEN 2
#define IP_ID 2
#define IP_FLPOS 2
#define IP_TTLIVE 1
#define IP_PROTOCOL 1
#define IP_CHECK_SUM 2
#define IP_ADDR 4
#define L4_PORT 2
#define TCP_SHAMT 9
void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack);

typedef struct{
    uint16_t uint16;
    uint32_t uint32;
    uint64_t uint64;
} uint_t;

void handleSignal(int nsignal);

pcap_t *descr = NULL;
uint64_t contador = 0;
uint8_t ipsrc_filter[IP_ALEN] = {NO_FILTER};
uint8_t ipdst_filter[IP_ALEN] = {NO_FILTER};
uint16_t sport_filter= NO_FILTER;
uint16_t dport_filter = NO_FILTER;

void handleSignal(int nsignal)
{
    (void) nsignal; // indicamos al compilador que no nos importa que nsignal no se utilice

    printf("Control C pulsado\n");
    pcap_breakloop(descr);
}

int main(int argc, char **argv)
{


    char errbuf[PCAP_ERRBUF_SIZE];

    int long_index = 0, retorno = 0;
    char opt;

    (void) errbuf; //indicamos al compilador que no nos importa que errbuf no se utilice. Esta linea debe ser eliminada en la entrega final.

    if (signal(SIGINT, handleSignal) == SIG_ERR) {
        printf("Error: Fallo al capturar la senal SIGINT.\n");
        exit(ERROR);
    }

    if (argc == 1) {
        printf("Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]\n", argv[0]);
        exit(ERROR);
    }

    static struct option options[] = {
        {"f", required_argument, 0, 'f'},
        {"i",required_argument, 0,'i'},
        {"ipo", required_argument, 0, '1'},
        {"ipd", required_argument, 0, '2'},
        {"po", required_argument, 0, '3'},
        {"pd", required_argument, 0, '4'},
        {"h", no_argument, 0, '5'},
        {0, 0, 0, 0}
    };

    //Simple lectura por parametros por completar casos de error, ojo no cumple 100% los requisitos del enunciado!
    while ((opt = getopt_long_only(argc, argv, "f:i:1:2:3:4:5", options, &long_index)) != -1) {
        switch (opt) {
        case 'i' :
            if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
                printf("Ha seleccionado más de una fuente de datos\n");
                pcap_close(descr);
                exit(ERROR);
            }

            if ( (descr = pcap_open_live(optarg, SNAPLEN, 0, 100, errbuf)) == NULL){
                printf("Error: pcap_open_live(): Interface: %s, %s %s %d.\n", optarg,errbuf,__FILE__,__LINE__);
                exit(ERROR);
            }
            break;

        case 'f' :
            if(descr) { // comprobamos que no se ha abierto ninguna otra interfaz o fichero
                printf("Ha seleccionado más de una fuente de datos\n");
                pcap_close(descr);
                exit(ERROR);
            }

            if ((descr = pcap_open_offline(optarg, errbuf)) == NULL) {
                printf("Error: pcap_open_offline(): File: %s, %s %s %d.\n", optarg, errbuf, __FILE__, __LINE__);
                exit(ERROR);
            }

            break;

        case '1' :
            if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipsrc_filter[0]), &(ipsrc_filter[1]), &(ipsrc_filter[2]), &(ipsrc_filter[3])) != IP_ALEN) {
                printf("Error ipo_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
                exit(ERROR);
            }

            break;

        case '2' :
            if (sscanf(optarg, "%"SCNu8".%"SCNu8".%"SCNu8".%"SCNu8"", &(ipdst_filter[0]), &(ipdst_filter[1]), &(ipdst_filter[2]), &(ipdst_filter[3])) != IP_ALEN) {
                printf("Error ipd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
                exit(ERROR);
            }

            break;

        case '3' :
            if ((sport_filter= atoi(optarg)) == 0) {
                printf("Error po_filtro.Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
                exit(ERROR);
            }

            break;

        case '4' :
            if ((dport_filter = atoi(optarg)) == 0) {
                printf("Error pd_filtro. Ejecucion: %s /ruta/captura_pcap [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
                exit(ERROR);
            }

            break;

        case '5' :
            printf("Ayuda. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
            exit(ERROR);
            break;

        case '?' :
        default:
            printf("Error. Ejecucion: %s <-f traza.pcap / -i eth0> [-ipo IPO] [-ipd IPD] [-po PO] [-pd PD]: %d\n", argv[0], argc);
            exit(ERROR);
            break;
        }
    }

    if (!descr) {
        printf("No selecciono ningún origen de paquetes.\n");
        return ERROR;
    }

    //Simple comprobacion de la correcion de la lectura de parametros
    printf("Filtro:");
    //if(ipsrc_filter[0]!=0)
    printf("ipsrc_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipsrc_filter[0], ipsrc_filter[1], ipsrc_filter[2], ipsrc_filter[3]);
    //if(ipdst_filter[0]!=0)
    printf("ipdst_filter:%"PRIu8".%"PRIu8".%"PRIu8".%"PRIu8"\t", ipdst_filter[0], ipdst_filter[1], ipdst_filter[2], ipdst_filter[3]);

    if (sport_filter!= NO_FILTER) {
        printf("po_filtro=%"PRIu16"\t", sport_filter);
    }

    if (dport_filter != NO_FILTER) {
        printf("pd_filtro=%"PRIu16"\t", dport_filter);
    }

    printf("\n\n");

    retorno=pcap_loop(descr,NO_LIMIT,analizar_paquete,NULL);
    switch(retorno)    {
        case OK:
            printf("Traza leída\n");
            break;
        case PACK_ERR:
            printf("Error leyendo paquetes\n");
            break;
        case BREAKLOOP:
            printf("pcap_breakloop llamado\n");
            break;
    }
    printf("Se procesaron %"PRIu64" paquetes.\n\n", contador);
    pcap_close(descr);
    return OK;
}



void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack)
{
    (void)user;
    uint16_t eth_protocol, posicion;
    uint8_t ip_protocol;

    printf("Nuevo paquete capturado el %s\n", ctime((const time_t *) & (hdr->ts.tv_sec)));
    contador++;
    int i = 0;

    printf("Direccion ETH destino = ");
    printf("%02X", pack[0]);

    for (i = 1; i < ETH_ALEN; i++) {
        printf("-%02X", pack[i]);
    }

    printf("\n");
    pack += ETH_ALEN;

    printf("Direccion ETH origen  = ");
    printf("%02X", pack[0]);

    for (i = 1; i < ETH_ALEN; i++) {
        printf("-%02X", pack[i]);
    }

    printf("\n");
    pack+=ETH_ALEN;
    // Ethernet
    eth_protocol = ntohs(*(uint16_t *)pack);
    printf("Protocolo             = ");
    printf("0x%04X", eth_protocol);
    printf("\n");
    if(eth_protocol != 0x0800){
        printf("El protocolo no es el esperado, no se imprimirá la información de los siguientes niveles.\n");
        return;
    }
    pack+=ETH_TLEN;
    // IP
    printf("Version IP            = ");
    printf("%"PRIu8"\n", pack[0]>>4);
    printf("Longitud de cabecera  = ");
    printf("%"PRIu8"\n", pack[0]&0x0F);
    pack+=IP_INIT;
    printf("Longitud total        = ");
    printf("%"PRIu16"\n", pack[0]);
    pack+=IP_TLEN+IP_ID;
    printf("Posición              = ");
    posicion = pack[0]&0x1FFF;
    printf("%"PRIu16"\n", posicion);
    pack+=IP_FLPOS;
    printf("Tiempo de vida        = ");
    printf("%"PRIu8"\n", pack[0]);
    pack+=IP_TTLIVE;
    printf("Protocolo             = ");
    ip_protocol =  pack[0];
    printf("%"PRIu8"\n", ip_protocol);
    pack+=IP_PROTOCOL+IP_CHECK_SUM;
    printf("Dirección IP origen   = ");
    printf("%"PRIu32"\n", pack[0]);
    pack+=IP_ADDR;
    printf("Dirección IP destino  = ");
    printf("%"PRIu32"\n", pack[0]);
    if(posicion != 0){
        return;
    }
    if(ip_protocol != 6 || ip_protocol != 17){
        printf("El protocolo no es el esperado, no se imprimirá la información de los siguientes niveles.\n");
        return;
    }
    // Transporte
    printf("Puerto origen         = ");
    printf("%"PRIu16"\n", pack[0]);
    pack+=L4_PORT;
    printf("Puerto destino        = ");
    printf("%"PRIu16"\n", pack[0]);
    pack+=L4_PORT;

    switch (ip_protocol) {
        case 6:  // TCP
            pack+=TCP_SHAMT;
            printf("SYN                   = ");
            printf("%"PRIu8"\n", pack[0]&0x02);
            printf("FIN                   = ");
            printf("%"PRIu8"\n", pack[0]&0x01);
        break;
        case 17: // UDP
            printf("Longitud              = ");
            printf("%"PRIu16"\n", pack[0]);
        break;
        default:
            fprintf(stderr, "Error en el nivel de transporte\n");
    }
    printf("\n\n");
}
