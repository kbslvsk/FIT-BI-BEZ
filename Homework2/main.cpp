/*
 ** @ Author: Jakub Sulovsky <sulovjak@fit.cvut.cz>
 *  @ Date: 22/04/2022
*/

#include <iostream>
#include <stdio.h>
#include <string.h>
#include <openssl/evp.h>
#include <string>


using namespace std;


int main( int argc, char ** argv )
{

    if ( argc != 4 )
    {
        printf ( "Invalid number of arguments!\n");
        return 1;

    }

    string action ( argv[1] );
    string mode   ( argv[2] );

    if ( ( ! ( action == "e" ) && ! ( action == "d" ) ) || ( ! ( mode == "ecb" ) && ! ( mode == "cbc" ) ) )
    {
        printf ("Invalid parameters!\n");
        return 2;
    }

    string fileName (argv[3]);

    std::transform( fileName.begin(), fileName.end(), fileName.begin(),
                   [](unsigned char c){ return tolower(c); });

    size_t pos = fileName.find(".tga");

    if ( pos == string::npos )
    {
        printf("Incorrect file name: .tga format required!\n");
        return 3;
    }

    fileName.erase( pos );

    unsigned char key[EVP_MAX_KEY_LENGTH] = "9876543210987654";
    unsigned char iv[EVP_MAX_IV_LENGTH] = "012345678901234";

    // ENCODE

    if ( action == "e" )
    {

        string ofName = fileName + "_" + mode + "_e.tga";

        FILE *inputFile = fopen(argv[3], "rb");

        if ( ! inputFile )
        {
            printf("File can't be opened!\n");
            return 4;
        }

        FILE *outputFile = fopen(ofName.c_str(), "wb");

        if ( ! outputFile )
        {
            printf("File can't be opened!\n");
            return 4;
        }

        if ( fseek ( inputFile, 0, SEEK_END ) )
        {
            printf ("Seek failed!\n");
            return 5;
        }

        long int fileSize = ftell(inputFile);

        if ( fileSize < 18 )
        {
            printf ("File is too short!\n");
            return 16;
        }

        // READING HEADER

        unsigned char idLength;
        unsigned char colorMapLengthLittleEndian[2];

        if ( fseek(inputFile, 0, SEEK_SET) )
        {
            printf ("Seek failed!\n");
            return 5;
        }

        if ( fread ( &idLength, 1, 1, inputFile ) != 1 )
        {
            printf ("Reading from file failed!\n");
            return 6;
        }

        if ( fseek(inputFile, 5, SEEK_SET) )
        {
            printf ("Seek failed!\n");
            return 5;
        }

        if ( fread(colorMapLengthLittleEndian, 1, 2, inputFile) != 2 )
        {
            printf ("Reading from file failed!\n");
            return 6;
        }


        int colorMapLength = 0;

        // 2B little endian value calculation

        colorMapLength += (colorMapLengthLittleEndian[0] + (colorMapLengthLittleEndian[1] << 8));

        if ( fseek(inputFile, 7, SEEK_SET) )
        {
            printf ("Seek failed!\n");
            return 5;
        }

        unsigned char bitsOnEntry;

        if ( fread( &bitsOnEntry, 1, 1, inputFile) != 1 )
        {
            printf ("Reading from file failed!!\n");
            return 6;
        }

        unsigned char bytesOnEntry = ( bitsOnEntry / 8 );

        if ( (( bitsOnEntry % 8 ) != 0) || ( bytesOnEntry != 0 && bytesOnEntry != 2 && bytesOnEntry != 3 && bytesOnEntry != 4 ))
        {
            printf("Invalid header!\n");
            return 16;
        }


        if ( fseek(inputFile, 0, SEEK_SET) )
        {
            printf ( "Seek failed\n");
            return 5;
        }

        unsigned char *header = (unsigned char *) malloc(18 + idLength + ( colorMapLength * bytesOnEntry ));

        if ( ! header )
        {
            printf("Memory allocation error\n");
            return 7;
        }

        if ( fread(header, 1, 18 + idLength + ( colorMapLength * bytesOnEntry ), inputFile) != ( 18 + idLength + ( colorMapLength * bytesOnEntry )))
        {
            printf ("Reading from file failed!!\n");
            return 6;
        }

        if ( fwrite(header, 1, 18 + idLength + ( colorMapLength * bytesOnEntry ), outputFile) != ( 18 + idLength + ( colorMapLength * bytesOnEntry )))
        {
            printf ("Writing to file failed!\n");
            return 8;
        }

        free(header);

        if ( fseek(inputFile, 18 + idLength + ( colorMapLength * bytesOnEntry ), SEEK_SET) )
        {
            printf ("Seek failed\n");
            return 9;
        }

        OpenSSL_add_all_ciphers();


        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            return 10;
        }

        if (mode == "cbc")
        {
            if ( EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1 )
            {
                printf ("EVP_ENCRYPTINIT_EX ERROR\n");
                return 11;
            }
        }
        else
        {
           if ( EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv) != 1 )
           {
               printf ("EVP_ENCRYPTINIT_EX ERROR\n");
               return 11;
           }
        }

        int stLength;
        unsigned char st[4140];
        unsigned char ot[4140];


        size_t bytesRead = 0;

        while ( ( bytesRead = ( fread(ot, 1, 4096, inputFile ))))
        {
            if ( bytesRead != 4096 )
            {
                if ( ! feof (inputFile))
                {
                    printf ("Reading from file failed!!\n");
                    return 6;
                }
            }

            if ( EVP_EncryptUpdate(ctx, st, &stLength, ot, bytesRead) != 1 )
            {
                printf ("EVP_ENCRYPTUPDATE ERROR\n");
                return 12;
            }

            if ( fwrite(st, 1, stLength, outputFile) != stLength )
            {
                printf ("Writing to file failed!!\n");
                return 8;
            }

            if ( feof(inputFile))
            {
                break;
            }
        }

        if ( ! feof(inputFile) )
        {
            printf ("Part of a file couldn't be loaded!\n");
            return 13;
        }

        if ( EVP_EncryptFinal_ex(ctx, st, &stLength) != 1 )
        {
            printf("EVP_ENCRYPTFINAL_EX ERROR\n");
            return 14;
        }

        if ( fwrite(st, 1, stLength, outputFile) != stLength )
        {
            printf("Writing to file failed!!\n");
            return 8;
        }

        EVP_CIPHER_CTX_free(ctx);

        if ( fclose(inputFile) == EOF )
        {
            printf("File couldn't be closed!\n");
            return 15;
        }

        if ( fclose(outputFile) == EOF )
        {
            printf("File couldn't be closed!\n");
            return 15;
        }

        return 0;

    }


    // DECODE
    else
    {

        string ofName = fileName + "_" + mode + "_d.tga";

        FILE *inputFile = fopen(argv[3], "rb");

        if ( !inputFile )
        {
            printf("File can't be opened!\n");
            return 3;
        }

        FILE *outputFile = fopen(ofName.c_str(), "wb");


        if ( !outputFile )
        {
            printf("File can't be opened!\n");
            return 3;
        }


        if ( fseek( inputFile, 0, SEEK_END ) )
        {
            printf ("Seek failed!\n");
            return 5;
        }

        long int fileSize = ftell(inputFile);

        if ( fileSize < 18 )
        {
            printf ("File is too short!\n");
            return 16;
        }

        // READING HEADER

        unsigned char idLength;
        unsigned char colorMapLengthLittleEndian[2];

        if ( fseek(inputFile, 0, SEEK_SET) )
        {
            printf ("Seek failed!\n");
            return 5;
        }

        if ( ! fread(&idLength, 1, 1, inputFile) )
        {
            printf("Reading from file failed!!\n");
            return 6;
        }

        if ( fseek(inputFile, 5, SEEK_SET) )
        {
            printf ("Seek failed!\n");
            return 5;
        }

        if ( fread(colorMapLengthLittleEndian, 1, 2, inputFile) != 2 )
        {
            printf("Reading from file failed!!\n");
            return 6;
        }


        int colorMapLength = 0;

        // 2B little endian value calculation

        colorMapLength += (colorMapLengthLittleEndian[0] + (colorMapLengthLittleEndian[1] << 8));

        if ( fseek(inputFile, 7, SEEK_SET) )
        {
            printf ("Seek failed!\n");
            return 5;
        }

        unsigned char bitsOnEntry;

        if ( fread( &bitsOnEntry, 1, 1, inputFile) != 1 )
        {
            printf ("Reading from file failed!\n");
            return 6;
        }

        unsigned char bytesOnEntry = ( bitsOnEntry / 8 );

        if ( (( bitsOnEntry % 8 ) != 0) || ( bytesOnEntry != 0 && bytesOnEntry != 2 && bytesOnEntry != 3 && bytesOnEntry != 4 ))
        {
            printf("Invalid header!\n");
            return 16;
        }

        if ( fseek( inputFile, 0, SEEK_SET) )
        {
            printf ("Seek failed!\n");
            return 5;
        }

        unsigned char *header = (unsigned char *) malloc(18 + idLength + ( colorMapLength * bytesOnEntry ));

        if ( ! header )
        {
            printf("Memory allocation failed!\n");
            return 7;
        }

        if ( fread(header, 1, 18 + idLength + ( colorMapLength * bytesOnEntry ), inputFile) != ( 18 + idLength + ( colorMapLength * bytesOnEntry ) ) )
        {
            printf("Reading from file failed!\n");
            return 6;
        }

        if ( fwrite(header, 1, 18 + idLength + ( colorMapLength * bytesOnEntry ), outputFile) != ( 18 + idLength + ( colorMapLength * bytesOnEntry ) ) )
        {
            printf("Writing to file failed!\n");
            return 8;
        }

        free(header);

        if ( fseek(inputFile, 18 + idLength + ( colorMapLength * bytesOnEntry ), SEEK_SET) )
        {
            printf ("Seek failed!\n");
            return 5;
        }

        OpenSSL_add_all_ciphers();

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();

        if (ctx == NULL)
        {
            return 10;
        }

        if (mode == "cbc")
        {
            if ( EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv) != 1 )
            {
                printf ("EVP_DECRYPTINIT_EX ERROR\n");
                return 11;
            }
        }

        else
        {
            if ( EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv) != 1 )
            {
                printf ("EVP_DECRYPTINIT_EX ERROR\n");
                return 11;
            }
        }


        int otLength;
        unsigned char st[4140];
        unsigned char ot[4140];


        size_t bytesRead = 0;

        while ( ( bytesRead = ( fread(st, 1, 4096, inputFile) )))
        {

            if ( bytesRead != 4096 )
            {
                if ( ! feof (inputFile))
                {
                    printf ("Reading from file failed!!\n");
                    return 6;
                }
            }

            if ( EVP_DecryptUpdate(ctx, ot, &otLength, st, bytesRead) != 1 )
            {
                printf ("EVP_DECRYPTUPDATE ERROR\n");
                return 12;
            }

            if ( fwrite(ot, 1, otLength, outputFile) != otLength )
            {
                printf ("Writing to file failed!!\n");
                return 8;

            }

            if ( feof(inputFile) )
            {
                break;
            }
        }

        if ( ! feof(inputFile) )
        {
            printf ("Part of a file couldn't be loaded!\n");
            return 13;
        }


        if ( EVP_DecryptFinal_ex(ctx, ot, &otLength) != 1 )
        {
            printf("EVP_DECRYPTFINAL_EX ERROR\n");
            return 14;
        }

        if ( fwrite( ot, 1, otLength, outputFile) != otLength )
        {
            printf("Writing to file failed!\n");
            return 8;
        }

        EVP_CIPHER_CTX_free(ctx);

        if ( fclose(inputFile) == EOF )
        {
            printf("File couldn't be closed\n");
            return 15;
        };

        if ( fclose(outputFile) == EOF )
        {
            printf("File couldn't be closed!\n");
            return 15;
        }

        return 0;

    }
}


