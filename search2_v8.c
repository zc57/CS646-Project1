#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>

/*CS646 Network Protocols Security           
 Team  4: Wolf, Martin | Crossey, Zach | Osabutey, Keren 
 Project 1, Task 2: Second Pre-Image Resistance Property*/


/*The parameters argc and argv provide a representation of the
program's command line. argc is the number of strings that
make up the command line (including the program name),
and argv is an array that contains those strings.
Here search1 md5 will be passed*/

int main(int argc, char *argv[]) { 

printf("********************************************************\n");
printf("*           CS646 Network Protocols Security           *\n");
printf("*                         Team  4                      *\n");
printf("*    Wolf, Martin | Crossey, Zach | Osabutey, Keren    *\n");
printf("*                     Project 1, Task 2                *\n");
printf("*          Second Pre-Image Resistance Property        *\n");
printf("*This C program, given the four-byte string 'harD',    *\n");
printf("*finds another four-byte array that hashes to the same *\n");
printf("*value as 'harD' does; considering only the first 32   *\n");
printf("*bits (4 bytes) of the md5 hash.                       *\n");
printf("*                                                      *\n"); 
printf("*       To run the program type: ./search2 md5         *\n"); 
printf("*                                                      *\n"); 
printf("*              'Patience is a virtue'                  *\n");
printf("*    Depending on the computing resources this may     *\n");
printf("*	         take up to 30 - 60 minutes.           *\n");
printf("********************************************************\n");  

     EVP_MD_CTX *mdctx;//'*' used as pointer
     const EVP_MD *md;
	 
	 //Step 1 Compute HashString of given four-byte string 'hardD'
     char charString1[] = "harD";
	//Declaring char and int variables
	//An unsigned char is a (unsigned) byte value (0 to 255)
    //unsigned char md_value_hex1[EVP_MAX_MD_SIZE] = "";
    //unsigned char md_value_computed1[EVP_MAX_MD_SIZE];
	 unsigned char md_value1[EVP_MAX_MD_SIZE];
     unsigned int md_len1, i;
	 
	//If no hashalgorythm is determined when running the code from CMD line
     if (argv[1] == NULL) {
         printf("Usage: mdtest digestname\n");
         exit(1);
     }

	//Returns an EVP_MD structure when digest name is passed. 
     md = EVP_get_digestbyname(argv[1]);
     if (md == NULL) {
         printf("Unknown message digest %s\n", argv[1]);
         exit(1);
     }

     mdctx = EVP_MD_CTX_new();
     EVP_DigestInit_ex(mdctx, md, NULL);
     EVP_DigestUpdate(mdctx, charString1, strlen(charString1));
     EVP_DigestFinal_ex(mdctx, md_value1, &md_len1);
     EVP_MD_CTX_free(mdctx);

     printf("Digest of charString1 %s is: \n", charString1);
     for (i = 0; i < md_len1; i++)
         printf("%02x", md_value1[i]);
     printf("\n");

    //Step 2 Compute md_value2	
  	//Declaring char and int variables
	//An unsigned char is a (unsigned) byte value (0 to 255)
    unsigned char md_value_hex2[EVP_MAX_MD_SIZE] = "";
    unsigned char md_value_computed2[EVP_MAX_MD_SIZE];
    unsigned char md_value2[EVP_MAX_MD_SIZE];
    unsigned int md_len2, i2;
 
    //Define unsigned charString with a maximum of four characters.
	//Unsigned char data type ranges from 0 to 255.
	//ASCII ranges from 0 to 255
    unsigned char charString2[4];
    int lowRange = 0;
    int hiRange = 255;
    int count = 0;
    	
	//Nested For Loops cycling through all possible four-byte strings
    for (int pos4 = lowRange; pos4 <= hiRange; pos4 = pos4 + 1) /*Outer Loop*/{
        for (int pos3 = lowRange; pos3 <= hiRange; pos3 = pos3 + 1) /*Inner Loop1*/{
            for (int pos2 = lowRange; pos2 <= hiRange; pos2 = pos2 + 1) /*Inner Loop2*/{
                for (int pos1 = lowRange; pos1 <= hiRange; pos1 = pos1 + 1)/*Inner Loop3*/ {
                    count += 1;
                    *md_value_hex = 0;
                    // printf("%i ", count);
                    charString[0] = pos1;
                    charString[1] = pos2;
                    charString[2] = pos3;
                    charString[3] = pos4;                
					//Calling EVP Interface functions
                    mdctx = EVP_MD_CTX_new();/*Allocates, initializes and returns a digest context*/
                    EVP_DigestInit_ex(mdctx, md, NULL);/*Set up digest context*/
                    // EVP_DigestUpdate(mdctx, charString, strlen(charString));
                    EVP_DigestUpdate(mdctx, charString2, 4);/*Hashes cnt bytes of data at d into the digest context ctx*/
                    EVP_DigestFinal_ex(mdctx, md_value2, &md_len2);/*Retrieves the digest value from ctx and places it in md*/
                    EVP_MD_CTX_free(mdctx);/*Cleans up digest context ctx and frees up the space allocated to it*/

                    // Convert md_value from ascii to hexadecimal string
                    char hex_string[3];
                    for (i = 0; i < md_len2; i++) {
						//Instead of printing on console, 
						//it stores output on char buffer which are specified in sprintf.
                        sprintf(hex_string, "%02x", md_value2[i]);//Converting ascii string to hex string
                        // printf("%s", hex_string);
						//Concetenate strings by appending a copy of the source string [hex_string]
						//to the destination string md_value_hex.
                        strcat(md_value_hex2, hex_string);//
                        // printf("%x", md_value[i]);
                    } 
                    // printf("\n");
					//Step 3 Compare md_value1==md_value2 [first 32 bites]    
					//Comparing the computed md5 hash value with the given one
                    if (strcmp(md_value1, md_value_hex2) == 0) {
                        printf("Given: %s == Computed: %s\n", md_value_hex, md_value_hex2);
                        printf("**********MATCH!**********\n");
						//This is the charString generated in the Outer/Inner Loops
                        printf("charString: %c%c%c%c\n", charString[0], charString[1], charString[2], charString[3]);
                        continue;
                    }
                }//End Inner Loop3
            } //End Inner Loop2
        } //End Inner Loop1
    } //End Outer Loop
//Step 4 If both matches, convert md_value2 into four-byte string
	printf("The four-byte value found: %s\n", charString2);
    exit(0);
}


