/*   scanner.c
 *   Scans ports 23 and 80 on a given ip/subnet/host
 *   Assumes subnet length 255 (scans from 0 to 255, subnet mask 255.255.255.0)
 *   Checks whether ports 23 and 80 are open to connections from localhost
 *   Relies on connect() errors for determining closed/open status
 *   Only IPV4, won't work with IPV6 (heck, I havn't seen an IPV6 router yet!) :-/
 *   A known vulnerability of ADSL modem/routers ;-)
 *   Author: Vikraman (vh4x0r @ Freenode) <vikraman.choudhury@gmail.com>
 *   Changelog: Added feature -- Scan hostnames
 *   06/2009
 */

/* includes for any linux box */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <netdb.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <arpa/inet.h>

int scan ( struct addrinfo * );  /* calls launch on specific ports */
int launch ( struct addrinfo * , int );  /* the actual socket->connect implementation */
inline void * Malloc ( size_t size );  /* cool wrapper for malloc() */
inline int strncnt ( char * ,size_t, int );  /* counts character occurences */
inline void display ( int, char * );  /* displays an impressive output */

int main ( int argc, char ** argv )  /* give subnet as argument */
{
  struct addrinfo * servinfo, hints;
  int rv, dot_count, num, result;
  char * ip;
  ip = (char *) Malloc ( 15 * sizeof (char) );
  
  if ( argc != 2 ) {
    fprintf ( stderr, "Usage: %s subnet/ip/hostname\n", argv[0] );  /* spit out an error if not correctly invoked */
    return 1;
  }

  dot_count = strncnt ( argv[1], sizeof argv[1], '.' );  /* count dots in argv[1] */

  if ( dot_count == 2 )  /* user passed a subnet */
    {
      /* generate ip addresses in subnet */
      for ( num = 0; num < 256; num++ ) {
	snprintf ( ip, 15, "%s.%d", argv[1], num );
	memset ( &hints, 0, sizeof hints );  /* setup hints */
	hints.ai_family = AF_INET;  /* IPV4 */
	hints.ai_socktype = SOCK_STREAM;  /* just to commit */
	if ( (rv = getaddrinfo ( ip, NULL, &hints, &servinfo )) != 0 ) {
	  fprintf ( stderr, "getaddrinfo: %s\n", gai_strerror(rv) );  /* getaddrinfo fails */
	  return 1;
	}
	result = scan ( servinfo );  /* scan the address */
	display ( result, ip );
      }
    }
  else  /* user passed an ip-address or a hostname */
    {
      /* resolve the ip/hostname using getaddrinfo() */
      memset ( &hints, 0, sizeof hints );  /* similar(?) */
      hints.ai_family = AF_INET;
      hints.ai_socktype = SOCK_STREAM;
      if ( (rv = getaddrinfo ( argv[1], NULL, &hints, &servinfo )) != 0 ) {
	fprintf ( stderr, "getaddrinfo: %s\n", gai_strerror(rv) );
	return 1;
      }
      result = scan ( servinfo );
      display ( result, argv[1] );
    }
  return 0;
}

inline void display ( int code, char * ip )  /* pretty straightforward */
{
  switch ( code )
    {
    case 3:
      printf ( "\n%s has ports 23 and 80 open!....... :-)", ip );
      printf ( "\nGood luck!....... ;-)\n" );
      break;
      
    case 1:
      printf ( "\n%s has port 23 open!....... :-)", ip );
      printf ( "\nBetter luck next time!....... ;-)\n" );
      break;
      
    case 2:
      printf ( "\n%s has port 80 open!....... :-)", ip );
      printf ( "\nBetter luck next time!....... ;-)\n" );
      break;

    case 0:
      printf ( "\n%s has ports 23 and 80 closed!....... :-(", ip );
      printf ( "\nBad luck!....... :-(\n" );
      break;
      
    default:
      printf ( "\nSome weird error while scanning %s! <panic>\n", ip );
    }
}

int scan ( struct addrinfo * servinfo )  /* get the linked list of addresses */
{
  struct addrinfo * p;
  int res_23, res_80;
  /* loop through the result nodes and scan each ip */
  for ( p = servinfo; p != NULL; p = p->ai_next ) {
    res_23 = launch ( p, 23 );  /* scan on port 23 */
    res_80 = launch ( p, 80 );  /* scan on port 80 */
  }
  /*return 0 on both failing, 0+2 on 23 failing, 1+0 on 80 failing, 3 on success, else 15(?) ;-) */
  return ( res_23 + 2*res_80 );
}

int launch (struct addrinfo * servinfo, int port )  /* socket->connect sequence on servinfo:port */
{
  int sockfd;
  struct sockaddr_in * temp;
  temp = (struct sockaddr_in *)servinfo->ai_addr;
  temp->sin_port = htons ( port );  /* need to htons, imp. */

  /* create socket, get socket descriptor */
  if ( (sockfd = socket ( servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol )) == -1 ) {
    perror ( "socket" );
    return 5;
  }

  /* connect on socket descriptor sockfd */
  if ( (connect ( sockfd, servinfo->ai_addr, servinfo->ai_addrlen )) == -1 ) {
    close ( sockfd );
    perror ( "connect" );
    return 0;
  }

  close ( sockfd );
  return 1;
}

inline int strncnt ( char * str, size_t size, int c )
{
  /* scan for c in str, return count */
  int count = 0;
  size_t index = 1;
  /* need to check maxsize, prevent buffer overflow vulnerabilities ;-) */
  while ( index <= size )
    {
      if ( *str == c )
	count++;
      str++;
      index++;
    }
  return count;
}

inline void * Malloc ( size_t size )
{
  void * temp;
  if ( (temp = malloc ( size )) == NULL) {
    fprintf ( stderr, "Huh! Out of memory! :-( \n" );
    exit (-1);
  }
  return temp;
}
