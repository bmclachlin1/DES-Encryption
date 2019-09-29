//**************************************************************
//Name: Blake McLachlin
//Date: September 16, 2019
//Program Name: Main.cpp
//Program function: Implementation of DES encryption algorithm
//in C++
//**************************************************************

#include <iostream>
#include <fstream>
#include <string>
#include <algorithm>
#include <cassert>
#include <unordered_map>
#include <vector>

//const variable declarations

//Initial Permutation (IP)
const int IP[64] = { 58, 50, 42, 34, 26, 18, 10, 2,
				     60, 52, 44, 36, 28, 20, 12, 4,
					 62, 54, 46, 38, 30, 22, 14, 6,
					 64, 56, 48, 40, 32, 24, 16, 8,
					 57, 49, 41, 33, 25, 17, 9, 1,
					 59, 51, 43, 35, 27, 19, 11, 3,
					 61, 53, 45, 37, 29, 21, 13, 5,
					 63, 55, 47, 39, 31, 23, 15, 7 };

//Inverse Initial Permutation (IP^(-1))
const int IIP[64] = { 40, 8, 48, 16, 56, 24, 64, 32,
					  39, 7, 47, 15, 55, 23, 63, 31,
					  38, 6, 46, 14, 54, 22, 62, 30,
					  37, 5, 45, 13, 53, 21, 61, 29,
					  36, 4, 44, 12, 52, 20, 60, 28,
					  35, 3, 43, 11, 51, 19, 59, 27,
					  34, 2, 42, 10, 50, 18, 58, 26,
					  33, 1, 41,  9, 49, 17, 57, 25 };

//Expansion Permutation (E)
const int EP[48] = { 32,  1,  2,  3,  4,  5,
					  4,  5,  6,  7,  8,  9,
					  8,  9, 10, 11, 12, 13,
					 12, 13, 14, 15, 16, 17,
					 16, 17, 18, 19, 20, 21,
					 20, 21, 22, 23, 24, 25,
					 24, 25, 26, 27, 28, 29,
					 28, 29, 30, 31, 32,  1 };

//Permutation Function (P)
const int P[32] = { 16, 7, 20, 21, 29, 12, 28, 17,
				   1, 15, 23, 26, 5, 18, 31, 10,
				   2, 8, 24, 14, 32, 27, 3, 9,
				   19, 13, 30, 6, 22, 11, 4, 25 };

//S-box Table 
int s_box[8][4][16] =
{ {
	14,4,13,1,2,15,11,8,3,10,6,12,5,9,0,7,
	0,15,7,4,14,2,13,1,10,6,12,11,9,5,3,8,
	4,1,14,8,13,6,2,11,15,12,9,7,3,10,5,0,
	15,12,8,2,4,9,1,7,5,11,3,14,10,0,6,13
},
{
	15,1,8,14,6,11,3,4,9,7,2,13,12,0,5,10,
	3,13,4,7,15,2,8,14,12,0,1,10,6,9,11,5,
	0,14,7,11,10,4,13,1,5,8,12,6,9,3,2,15,
	13,8,10,1,3,15,4,2,11,6,7,12,0,5,14,9
},


{
	10,0,9,14,6,3,15,5,1,13,12,7,11,4,2,8,
	13,7,0,9,3,4,6,10,2,8,5,14,12,11,15,1,
	13,6,4,9,8,15,3,0,11,1,2,12,5,10,14,7,
	1,10,13,0,6,9,8,7,4,15,14,3,11,5,2,12
},
{
	7,13,14,3,0,6,9,10,1,2,8,5,11,12,4,15,
	13,8,11,5,6,15,0,3,4,7,2,12,1,10,14,9,
	10,6,9,0,12,11,7,13,15,1,3,14,5,2,8,4,
	3,15,0,6,10,1,13,8,9,4,5,11,12,7,2,14
},
{
	2,12,4,1,7,10,11,6,8,5,3,15,13,0,14,9,
	14,11,2,12,4,7,13,1,5,0,15,10,3,9,8,6,
	4,2,1,11,10,13,7,8,15,9,12,5,6,3,0,14,
	11,8,12,7,1,14,2,13,6,15,0,9,10,4,5,3
},
{
	12,1,10,15,9,2,6,8,0,13,3,4,14,7,5,11,
	10,15,4,2,7,12,9,5,6,1,13,14,0,11,3,8,
	9,14,15,5,2,8,12,3,7,0,4,10,1,13,11,6,
	4,3,2,12,9,5,15,10,11,14,1,7,6,0,8,13
},
{
	4,11,2,14,15,0,8,13,3,12,9,7,5,10,6,1,
	13,0,11,7,4,9,1,10,14,3,5,12,2,15,8,6,
	1,4,11,13,12,3,7,14,10,15,6,8,0,5,9,2,
	6,11,13,8,1,4,10,7,9,5,0,15,14,2,3,12
},
{
	13,2,8,4,6,15,11,1,10,9,3,14,5,0,12,7,
	1,15,13,8,10,3,7,4,12,5,6,11,0,14,9,2,
	7,11,4,1,9,12,14,2,0,6,10,13,15,3,5,8,
	2,1,14,7,4,10,8,13,15,12,9,0,3,5,6,11
} };



const int shift_table[16] = { 1, 1, 2, 2,
							  2, 2, 2, 2,
							  1, 2, 2, 2,
							  2, 2, 2, 1 };

const int PC_1[56] = { 57, 49, 41, 33, 25, 17,  9,
					    1, 58, 50, 42, 34, 26, 18,
					   10,  2, 59, 51, 43, 35, 27,
					   19, 11,  3, 60, 52, 44, 36,
					   63, 55, 47, 39, 31, 23, 15,
					    7, 62, 54, 46, 38, 30, 22,
					   14,  6, 61, 53, 45, 37, 29,
					   21, 13,  5, 28, 20, 12,  4 };

const int PC_2[48] = { 14, 17, 11, 24,  1,  5,
						3, 28, 15,  6, 21, 10,
					   23, 19, 12,  4, 26,  8,
					   16,  7, 27, 20, 13,  2,
					   41, 52, 31, 37, 47, 55,
					   30, 40, 51, 45, 33, 48,
					   44, 49, 39, 56, 34, 53,
					   46, 42, 50, 36, 29, 32
};

using namespace std;

//**********************************************************************
//Function Prototypes Start
//**********************************************************************
string hex_to_bin(const string& hex);

string bin_to_hex(const string& bin);

string bin_to_dec(const string& bin);

string dec_to_bin(const string& dec);

string XOR(const string& s1, const string& s2);

string apply_s_box(const string& bit_stream);

string apply_P(const string& bit_stream);

string apply_IP(const string& plaintext);

string apply_IIP(const string& bit_stream);

string apply_EP(const string& right);

string apply_PC1(const string& key);

void perform_DES();

string round_function(const string& left32, const string& right32, const vector<string>& subkeys);

string read_data(const string& fileName);

void write_data(const string& fileName, const string& data);

vector<string> generate_subkeys(const string& key);
//**********************************************************************
//Function Prototypes End
//**********************************************************************

int main() {
	perform_DES();
	cout << "enter anything to exit prog" << endl;
	system("pause");
}

//**********************************************************************
//Name: apply_s_box
//Purpose: takes a 48 length bit stream and maps it to 32 bits using 
//s-boxes
//returns: string
//**********************************************************************
string apply_s_box(const string& bit_stream) {
	assert(bit_stream.length() == 48);
	string new_text, text_segment, row_val, left, right, col_val = "";
	int select_box, selected_val, row_val_dec, col_val_dec = 0;
	for (unsigned int i = 0; i < 48; i += 6) {
		left = bit_stream.substr(i, 1);
		right = bit_stream.substr(i + 5, 1);
		row_val = left + right;
		row_val_dec = stoi(bin_to_dec(row_val));
		col_val = bit_stream.substr(i + 1, 4);
		col_val_dec = stoi(bin_to_dec(col_val));
		select_box = i / 6; 
		selected_val = s_box[select_box][row_val_dec][col_val_dec];
		text_segment = dec_to_bin(to_string(selected_val));
		new_text += text_segment;
	}
	return new_text;
}

//**********************************************************************
//Name: apply_P
//Purpose: applies Permutation function (P) to the 32-bit result from 
//the S-box and gives back a 32-bit string
//returns: string
//**********************************************************************
string apply_P(const string& bit_stream) {
	string new_text = "";
	for (unsigned int i = 0; i < 32; i++)
		new_text += bit_stream[P[i] - 1];
	return new_text;
}


//**********************************************************************
//Name: apply_IP
//Purpose: applies initial permutation (IP) to the plaintext input
//returns: string
//**********************************************************************
string apply_IP(const string& plaintext) {
	string new_text = "";
	for (unsigned int i = 0; i < 64; i++) {
		new_text += plaintext[IP[i] - 1];
	}
	return new_text;
}

//**********************************************************************
//Name: apply_IIP
//Purpose: applies inverse initial permutation (IIP) to the bit stream
//returns: string
//**********************************************************************
string apply_IIP(const string& bit_stream) {
	string new_text = "";
	for (unsigned int i = 0; i < 64; i++)
		new_text += bit_stream[IIP[i] - 1];
	return new_text;
}

//**********************************************************************
//Name: apply_EP
//Purpose: applies expansion permutation to right side input of round
//function
//returns: string
//**********************************************************************
string apply_EP(const string& right) {
	string new_text = "";
	for (unsigned int i = 0; i < 48; i++) {
		new_text += right[EP[i] - 1];
	}
	return new_text;
}

//**********************************************************************
//Name: apply_PC1
//Purpose: applies Permuted Choice One to the original 64-bit key
//which turns it into a 56-bit key
//returns: string
//**********************************************************************
string apply_PC1(const string& key) {
	string new_key = "";
	for (unsigned int i = 0; i < 56; i++) {
		new_key += key[PC_1[i] - 1]; 
	}
	return new_key;
}

//**********************************************************************
//Name: generate_subkeys
//Purpose: generates all 16 subkeys used for the DES encryption 
//algorithm
//Returns: string pointer (array of strings) 
//**********************************************************************
vector<string> generate_subkeys(const string& key) {
	vector<string> subkeys;
	//variable declarations
	string left, right, newLeft, newRight, temp_key, new_key = "";
	for (unsigned int i = 0; i < 16; i++) {
		//split 56-bit string into two equal 28-bit parts
		if (i == 0) {
			//for the first round, you use the parameter passed to the function
			left = key.substr(0, 28);
			right = key.substr(28, 28);
		}
		else {
			//for all other rounds, you use the key from the left shifts but before applying PC_2
			left = temp_key.substr(0, 28);
			right = temp_key.substr(28, 28);
		}
		//apply left shifts on left and right halves
		if (shift_table[i] == 1) {
			newLeft = left.substr(1, 27) + left.substr(0, 1);
			newRight = right.substr(1, 27) + right.substr(0, 1);
		}
		else {
			newLeft = left.substr(2, 26) + left.substr(0, 2);
			newRight = right.substr(2, 26) + right.substr(0, 2);
		}
		//concatenate left and right
		temp_key = newLeft + newRight;
		//apply permuted choice 2
		new_key = ""; //reset from last round of subkey generation
		for (int j = 0; j < 48; j++) {
			new_key += temp_key[PC_2[j] - 1]; //-1 for indexing
		}
		subkeys.push_back(new_key);
	}
	return subkeys;
}

//**********************************************************************
//Name: perform_DES
//Purpose: Performs DES encryption/decryption algorithm
//returns: string
//**********************************************************************
void perform_DES() {
	string round_result, encrypted, left, right, plaintext_hex, plaintext_bin, key_hex, key_bin, fileName = "";
	string choice;
	vector<string> subkeys;
	cout << "Enter E for encryption and D for decryption: ";
	getline(cin, choice);
	cout << "Input the key in hexadecimal form: ";
	getline(cin, key_hex);
	cout << "Input the file name to encrypt (e.g. data.txt): ";
	getline(cin, fileName);
	plaintext_hex = read_data(fileName);
	plaintext_bin = hex_to_bin(plaintext_hex);
	plaintext_bin = apply_IP(plaintext_bin);
	left = plaintext_bin.substr(0, 32);
	right = plaintext_bin.substr(32, 32);
	key_bin = hex_to_bin(key_hex);
	key_bin = apply_PC1(key_bin);
	subkeys = generate_subkeys(key_bin);
	if (choice == "D")
		reverse(subkeys.begin(), subkeys.end());
	round_result = round_function(left, right, subkeys);
	left = round_result.substr(32, 32);
	right = round_result.substr(0, 32);
	encrypted = left + right;
	encrypted = apply_IIP(encrypted);
	encrypted = bin_to_hex(encrypted);
	write_data(fileName, encrypted);
}

string read_data(const string& fileName) {
	ifstream fileIn;
	string text = "";
	fileIn.open("./src/" + fileName);
	if (!fileIn.is_open()) {
		cerr << "Invalid file name. Closing the program..." << endl;
		exit(0);
	}
	getline(fileIn, text);
	return text;
}

void write_data(const string& fileName, const string& data) {
	ofstream fileOut;
	string text = data;
	fileOut.open("./src/" + fileName);
	if (!fileOut.is_open()) {
		cerr << "Invalid file namee. Closing the program..." << endl;
		exit(0);
	}
	fileOut << data;
}

//**********************************************************************
//Name: round_function
//Purpose: Performs 16 rounds of the round function for DES
//returns: string
//**********************************************************************
string round_function(const string& left32, const string& right32, const vector<string>& subkeys) {
	string EP, EP_XOR_K, s_box, permute, left, previousLeft, right, encrypted = "";
	for (unsigned int i = 0; i < subkeys.size(); i++) {
		if (i == 0) {
			left = left32;
			right = right32;
		}
		EP = apply_EP(right);
		EP_XOR_K = XOR(EP, subkeys[i]);
		s_box = apply_s_box(EP_XOR_K);
		permute = apply_P(s_box);
		previousLeft = left;
		left = right;
		right = XOR(previousLeft, permute);
	}
	encrypted = left + right;
	return encrypted;
}

//**********************************************************************
//Name: hex_to_bin
//Purpose: Converts a 16-bit hexadecimal number into a 64-bit binary 
//number
//Returns: string
//**********************************************************************
string hex_to_bin(const string& hex) {
	assert(hex.length() <= 16);
	string bin = "";
	unordered_map<char, string> mp;
	mp['0'] = "0000";
	mp['1'] = "0001";
	mp['2'] = "0010";
	mp['3'] = "0011";
	mp['4'] = "0100";
	mp['5'] = "0101";
	mp['6'] = "0110";
	mp['7'] = "0111";
	mp['8'] = "1000";
	mp['9'] = "1001";
	mp['A'] = "1010";
	mp['B'] = "1011";
	mp['C'] = "1100";
	mp['D'] = "1101";
	mp['E'] = "1110";
	mp['F'] = "1111";
	for (unsigned int i = 0; i < hex.size(); i++) {
		bin += mp[hex[i]];
	}
	int zeros_to_prepend = 64 - bin.length();
	for (int i = 0; i < zeros_to_prepend; i++) {
		bin.insert(0, "0");
	}
	return bin;
}

//**********************************************************************
//Name: bin_to_hex
//Purpose: converts a 64-bit binary number to a 16-bit hexadecimal
//number
//Returns: string
//**********************************************************************
string bin_to_hex(const string& bin) {
	assert(bin.length() == 64);
	string hex = "";
	unordered_map<string, string> mp;
	mp["0000"] = "0";
	mp["0001"] = "1";
	mp["0010"] = "2";
	mp["0011"] = "3";
	mp["0100"] = "4";
	mp["0101"] = "5";
	mp["0110"] = "6";
	mp["0111"] = "7";
	mp["1000"] = "8";
	mp["1001"] = "9";
	mp["1010"] = "A";
	mp["1011"] = "B";
	mp["1100"] = "C";
	mp["1101"] = "D";
	mp["1110"] = "E";
	mp["1111"] = "F";
	for (unsigned int i = 0; i < bin.length(); i += 4) {
		string ch = "";
		ch += bin[i];
		ch += bin[i + 1];
		ch += bin[i + 2];
		ch += bin[i + 3];
		hex += mp[ch];
	}
	return hex;
}

//**********************************************************************
//Name: bin_to_dec
//Purpose: converts a binary number to a decimal number
//Returns: string
//**********************************************************************
string bin_to_dec(const string& bin) {
	string dec = "";
	unordered_map<string, string> mp;
	//for outer bits 1 & 6 (row bits)
	mp["00"] = "0";
	mp["01"] = "1";
	mp["10"] = "2";
	mp["11"] = "3";
	//for inner bits 2-5 (col bits)
	mp["0000"] = "0";
	mp["0001"] = "1";
	mp["0010"] = "2";
	mp["0011"] = "3";
	mp["0100"] = "4";
	mp["0101"] = "5";
	mp["0110"] = "6";
	mp["0111"] = "7";
	mp["1000"] = "8";
	mp["1001"] = "9";
	mp["1010"] = "10";
	mp["1011"] = "11";
	mp["1100"] = "12";
	mp["1101"] = "13";
	mp["1110"] = "14";
	mp["1111"] = "15";
	dec = mp[bin];
	return dec;
}

//**********************************************************************
//Name: dec_to_bin
//Purpose: converts a decimal number to a binary number
//Returns: string
//**********************************************************************
string dec_to_bin(const string& dec) {
	string bin = "";
	unordered_map<string, string> mp;
	mp["0"] = "0000";
	mp["1"] = "0001";
	mp["2"] = "0010";
	mp["3"] = "0011";
	mp["4"] = "0100";
	mp["5"] = "0101";
	mp["6"] = "0110";
	mp["7"] = "0111";
	mp["8"] = "1000";
	mp["9"] = "1001";
	mp["10"] = "1010";
	mp["11"] = "1011";
	mp["12"] = "1100";
	mp["13"] = "1101";
	mp["14"] = "1110";
	mp["15"] = "1111";
	bin = mp[dec];
	return bin;
}

//**********************************************************************
//Name: XOR
//Purpose: takes two binary strings and does XOR on each individual bit
//in the string
//returns: string
//**********************************************************************
string XOR(const string& s1, const string& s2) {
	assert(s1.length() == s2.length());
	string new_string = "";
	for (unsigned int i = 0; i < s1.length(); i++) {
		if (s1[i] == s2[i])
			new_string += "0";
		else
			new_string += "1";
	}
	return new_string;
}
