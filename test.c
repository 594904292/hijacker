#include <stdio.h>
#include <string.h>

int main ()
{
   int len;
   char url[1024];
   const char str1[] = "GET / HTTP/1.1\r\n";
   const char str2[] = "\r\n";

   const char payload[] = "GET / HTTP/1.1\r\nzzzzzzzzzzzzzzzzzzzz";

   len = strcspn(payload, "\r\n");


   memcpy(url, payload+4, len-13);
   memset(url+len-13, 0, 1);

   //puts(url);
   printf("cspn:%d, len %d, '%s' \n", len, strlen(url), url);

   //printf("Length of initial segment matching %d, total %d\n", len, strlen(str1) );
   
   return(0);
}
