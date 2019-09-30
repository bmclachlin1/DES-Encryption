To compile the program using g++ type:

g++ -std=c++11 -o main.exe Main.cpp

in the program directory with all the files.

For the file you are encrypting/decrypting you can name it anything you want as the program will prompt you for the name of the file. For example if your file you are encrypting is named data.txt, type data.txt and then enter when asked for the file name.

To run the program, type the name of the executable main.exe or main.

The program will prompt you for encryption or decryption. Type E then enter for encryption or D then enter for decryption. Next, the program will prompt you for a 16-bit key in hexadecimal. Type in the key then press enter. Then, the program will ask you for the name of the file you are encrypting/decrypting. Enter the name of the file then press enter. The program will then run and close down once it is done encrypting/decrypting. The encrypted/decrypted plaintext will appear in the same file that you passed into the program. For example, if you passed a file named data.txt to the program with the plaintext to be encrypted/decrypted, when the program is done running, it will overwrite the plaintext with the encrypted/decrypted version of the plaintext. 

Note: The program assumes that the plaintext and key entered are 16-bit hexadecimal numbers. If you pass anything other than a 16-bit hexadecimal number to the program the program may crash or behave weirdly.
