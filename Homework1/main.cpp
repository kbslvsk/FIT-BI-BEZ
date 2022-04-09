#include <iostream>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <string>

using namespace std;


int main( int argc, char ** argv )
{

    int startLength = 0; // length of starting sequence of '0'
    if ( argc != 2 || ( sscanf ( argv[1], "%d", &startLength )) != 1 )
    {
        printf ( "Invalid arguments!\n");
        return 1;
    }

    if ( startLength < 0 || startLength > 512 )
    {
        printf ( "Invalid length!\n"); return 2;
    }

    char openText[] = "000000000000000000000000000000000000000000000000000000000";
    char hashFunction[] = "sha512";

    EVP_MD_CTX * ctx;  // context structure

    const EVP_MD * type; // type of used hash function

    unsigned char hash[EVP_MAX_MD_SIZE]; // char array for hash - 64 bytu (max for sha 512)

    unsigned int length;  // final length of hash

    OpenSSL_add_all_digests(); // Initialization of OPENSSL functions

    type = EVP_get_digestbyname(hashFunction); // Getting hash function, that should be used

    // Checking, whether the correct hash function was entered

    if (!type) {
        printf("Hash %s doesn't exist.\n", hashFunction);
        return 3;
    }

    ctx = EVP_MD_CTX_new(); // create context for hashing
    if ( ctx == NULL )      // Check, whether previous operation was successful
        return 4;


    for ( int i = 0 ; i < INT32_MAX ; ++i ) { // Iterating through range of int to generate texts to be hashed
        string text = to_string( i );
        for ( int i = 0 ; i < text.size() ; ++i ) {
            openText[i] = text[i];
        }
        openText[text.size()] = '\0';


        if (!EVP_DigestInit_ex(ctx, type, NULL)) // context setup for our hash type
            return 5;

        if (!EVP_DigestUpdate(ctx, openText, strlen(openText))) // feed the message in
            return 6;

        if (!EVP_DigestFinal_ex(ctx, hash, &length)) // get the hash
            return 7;

        bool valid = true; // variable that indicates, whether our text starts with enough '0's

        for ( int i = 0 ; i < startLength ; ++i )
        {
            int byte = ( i / 8 ); // number of bit / 8

            if ( ( hash[byte] >> ( 7 - ( i % 8 )) ) & 0x01 ) // Checks specific bit of given byte. If it is 1: WRONG
            {
             valid = false;
             break;
            }
        }

        if ( valid ) // if the starting sequence of '0' is long enough
        {
            printf("Text: "); // print open text hexadecimally
            for ( int i = 0; i < strlen(openText);++i )
            {
              printf ("%02x", openText[i]);
            }

            printf ("\nHash: "); // print hash of text hexadecimally
            for ( int i = 0; i < length ; ++i )
            {
                printf ("%02x", hash[i]);
            }
            break;
        }
    }

    EVP_MD_CTX_free(ctx);

    return 0;
}
