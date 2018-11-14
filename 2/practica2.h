#ifndef PRACTICA2
#define PRACTICA2

/**
 * Manejador de la señal SIGINT que termina la ejecución del programa.
 */
void handleSignal(int nsignal);

/**
 * Función de callback de pcap_loop. Imprime los campos pedidos en el enunciado
 * conforme procesa los paquetes.
 */
void analizar_paquete(u_char *user,const struct pcap_pkthdr *hdr, const uint8_t *pack);

#endif
