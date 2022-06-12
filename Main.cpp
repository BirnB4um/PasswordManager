#include <iostream>
#include <thread>
#include <vector>
#include <fstream>

#include "xxtea.h"
#include "SHA256.h"

bool save_to_file(std::string file_name, const char output_data[], const int data_size) {
	if (file_name == "")
		return false;

	auto myfile = std::fstream(file_name, std::ios::out | std::ios::binary);
	myfile.write((char*)output_data, data_size);
	myfile.close();

	return true;
}

bool read_from_file(std::string file_name, std::vector<char>& input_data) {
	if (file_name == "")
		return false;

	std::ifstream input(file_name, std::ios::binary);
	if (!input.good())
		return false;

	input_data = std::vector<char>((std::istreambuf_iterator<char>(input)), (std::istreambuf_iterator<char>()));
	input.close();
	return true;
}

//30 zeichen = name
// username, email, pw, zusatz

//file layout
/*

 -1 byte -> version number
 -32 bytes -> pw hash (sha256)
 -4 bytes -> number of items (unsiged int)
 -...bytes -> private data

*/

/*
PRIVATE DATA LAYOUT:

-login_place
-username
-email
-password
-additional

-login_place
-username
-...

*/

SHA256 sha;
std::vector<char*> login_places;
std::vector<char*> usernames;
std::vector<char*> emails;
std::vector<char*> passwords;
std::vector<char*> additionals;
const int login_length = 80;
const int username_length = 80;
const int email_length = 80;
const int password_length = 80;
const int additional_length = 240;
int length_of_one_item = login_length + username_length + email_length + password_length + additional_length;

uint8_t* pw = new uint8_t[1000];
uint8_t* pw_hash = nullptr;

int item_count = 0;
size_t encrypted_private_data_length = 0;
uint8_t* encrypted_private_data = nullptr;
uint8_t* decrypted_private_data = nullptr;

void clear_and_free_all_data() {
	memset(pw, 0, 1000);
	delete[] pw;

	if (decrypted_private_data != nullptr) {
		memset(decrypted_private_data, 0, item_count * length_of_one_item);
		delete[] decrypted_private_data;
	}
}

void add_item(char* login_place, char* username, char* email, char* password, char* additional) {
	uint8_t* old_ptr = decrypted_private_data;
	decrypted_private_data = new uint8_t[item_count * length_of_one_item + length_of_one_item];
	memcpy(decrypted_private_data, old_ptr, item_count * length_of_one_item);
	if (old_ptr != nullptr) {
		memset(old_ptr, 0, item_count * length_of_one_item);
		delete[] old_ptr;
	}
	memset(&(decrypted_private_data[item_count * length_of_one_item]), 0, length_of_one_item);

	//add data to list
	memcpy(&(decrypted_private_data[item_count * length_of_one_item]), login_place, strlen(login_place) >= login_length ? login_length - 1 : strlen(login_place));
	memcpy(&(decrypted_private_data[item_count * length_of_one_item + login_length]), username, strlen(username) >= username_length ? username_length - 1 : strlen(username));
	memcpy(&(decrypted_private_data[item_count * length_of_one_item + login_length + username_length]), email, strlen(email) >= email_length ? email_length - 1 : strlen(email));
	memcpy(&(decrypted_private_data[item_count * length_of_one_item + login_length + username_length + email_length]), password, strlen(password) >= password_length ? password_length - 1 : strlen(password));
	memcpy(&(decrypted_private_data[item_count * length_of_one_item + login_length + username_length + email_length + password_length]), additional, strlen(additional) >= additional_length ? additional_length - 1 : strlen(additional));

	item_count++;
}

uint8_t* get_hash(uint8_t* data, size_t size) {
	SHA256 sha;
	sha.update(data, size);
	return sha.digest();
}

int main() {
	//create file if not existent
	std::ifstream input("encrypted.pw", std::ios::binary);
	if (!input.good()) {
		std::cout << "ERROR: file 'encrypted.pw' is missing" << std::endl;

		std::cout << "Create new file? (y/n):";
		char in;
		std::cin >> in;
		if (int(in) == 121 || int(in) == 89) {
			system("cls");
			std::cout << "set password for new file:";
			memset(pw, 0, 1000);
			std::cin >> pw;
			std::cout << "new password set to:" << pw << std::endl;

			char out_data[37];
			out_data[0] = 1;//version
			uint8_t* hash = get_hash((uint8_t*)pw, 1000);
			memcpy(&(out_data[1]), hash, 32);
			delete[] hash;
			out_data[33] = 0;
			out_data[34] = 0;
			out_data[35] = 0;
			out_data[36] = 0;
			save_to_file("encrypted.pw", out_data, 37);
		}
		else {
			return 0;
		}
	}
	input.close();

	//get data from file
	std::vector<char> file_data;
	if (!read_from_file("encrypted.pw", file_data)) {
		std::cout << "ERROR: couldnt read from file" << std::endl;
		std::cin.get();
		return 0;
	}

	//check version
	if (file_data[0] != 1) {
		system("cls");
		std::cout << "ERROR: outdated file-version!" << std::endl;
		clear_and_free_all_data();
		std::cin.get();
		return 0;
	}

	//copy data from file
	pw_hash = (uint8_t*)&(file_data[1]);//pw hash
	memcpy(&item_count, (int*)&(file_data[33]), 4);//item count
	if (item_count > 0) {
		encrypted_private_data = (uint8_t*)&(file_data[37]);//encrypted data
		encrypted_private_data_length = file_data.size() - 37;
	}

	system("cls");
	int incorrect_pw_count = 0;
	bool correct_pw = false;
	while (!correct_pw)
	{
		std::cout << "input password to file:";
		memset(pw, 0, 1000);
		std::cin >> pw;

		uint8_t* sha_out = get_hash((uint8_t*)pw, 1000);
		correct_pw = true;
		for (int i = 0; i < 32; i++) {
			if (sha_out[i] != pw_hash[i]) {
				correct_pw = false;
				incorrect_pw_count++;
				if (incorrect_pw_count > 4) {
					delete[] sha_out;
					clear_and_free_all_data();
					return 0;
				}
				system("cls");
				std::cout << "wrong password! (wait " << incorrect_pw_count << " seconds to try again)" << std::endl;
				std::this_thread::sleep_for(std::chrono::milliseconds(1000 * incorrect_pw_count));
				break;
			}
		}
		delete[] sha_out;
	}

	system("cls");

	//decrypt data
	size_t out_len = 0;
	if (encrypted_private_data != nullptr) {
		decrypted_private_data = (uint8_t*)xxtea_decrypt(encrypted_private_data, encrypted_private_data_length, pw, &out_len);
	}

	//create lists
	for (long i = 0; i < item_count; i++) {
		login_places.push_back((char*)&(decrypted_private_data[i * length_of_one_item]));
		usernames.push_back((char*)&(decrypted_private_data[i * length_of_one_item + login_length]));
		emails.push_back((char*)&(decrypted_private_data[i * length_of_one_item + login_length + username_length]));
		passwords.push_back((char*)&(decrypted_private_data[i * length_of_one_item + login_length + username_length + email_length]));
		additionals.push_back((char*)&(decrypted_private_data[i * length_of_one_item + login_length + username_length + email_length + password_length]));
	}

	//show full short-list = only website names
	for (char* name : login_places) {
		std::cout << name << "\n";
	}
	std::cout << "\n";

	for (int i = 0; i < item_count; i++) {
		std::cout << login_places[i] << " as " << usernames[i] << " with email:" << emails[i] << "\n";
		std::cout << "pw:" << passwords[i] << " | additional:" << additionals[i] << "\n";
		std::cout << std::endl;
	}

	char login_place[] = "insta";
	char username[] = "thimo";
	char email[] = "lol.com";
	char password[] = "hallooo";
	char additional[] = "dies ist ein langer text der nicht ganz auf die fläche passt.";
	//add_item(login_place, username, email, password, additional);

	//wait for command input:
	//help
	//long - outputs long list with names and all data
	//short - outputs short list with only names
	//[number] or name - prints all information of single selected item
	//add - adds new item -> asks for name,email,... -> add item to list and saves immediately
	//remove - remove item from list -> prints whole list -> asks for number/name -> deletes it and saves immediately
	//new_pw - set new password
	//exit - overrides everything it saved into memory -> exits

	encrypted_private_data = (uint8_t*)xxtea_encrypt(decrypted_private_data, item_count * length_of_one_item, pw, &out_len);
	uint8_t* save_data = new uint8_t[37 + out_len];
	save_data[0] = 1;//version
	memcpy(&(save_data[1]), pw_hash, 32);
	memcpy(&(save_data[33]), &item_count, sizeof(int));
	memcpy(&(save_data[37]), encrypted_private_data, out_len);
	save_to_file("encrypted.pw", (char*)save_data, 37 + out_len);

	//std::cout << "test" << "\r" << std::flush;
	clear_and_free_all_data();
	return 0;
}