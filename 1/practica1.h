#ifndef PRACTICA1
#define PRACTICA1

void handle(int nsignal);

void fa_nuevo_paquete(uint8_t *usuario, const struct pcap_pkthdr* cabecera, const uint8_t* paquete);

/**
 * Checks if given string is a integer number.
 *
 * char *s: String to be checked.
 */
bool aredigits(char *s);


/**
 * Prints the content of the packet in 2 chars hex-format.
 *
 * uint32_t caplen: number of bytes of the packet's content.
 * uint8_t *pkt   : pointer to the packet.
 */
void print_pkt_hex(const uint32_t caplen, const uint8_t *pkt);


#endif
