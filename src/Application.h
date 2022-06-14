#pragma once
#include <iostream>
#include <thread>
#include <vector>
#include <fstream>

#include "xxtea.h"
#include "SHA256.h"

#define ADDITIONAL_WAIT_TIME 1000
#define MAX_TRIES 3

class Application
{
private:
	//VARIABLES
	int item_count;
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
	int length_of_one_item;

	uint8_t* pw;
	uint8_t* pw_hash;

	size_t encrypted_private_data_length;
	uint8_t* encrypted_private_data;
	uint8_t* decrypted_private_data;

	//FUNCTIONS
	bool read_from_file(std::string file_name, std::vector<char>& input_data);
	bool save_to_file(std::string file_name, const char output_data[], const int data_size);
	uint8_t* get_hash(uint8_t* data, size_t size);
	bool is_string_number(std::string str);
	void clear_input_buffer();
	void save();
	void print_help();
	void print_short_list();
	void shrink_data_to_lists();
	void update_lists();
	void add_item(char* login_place, char* username, char* email, char* password, char* additional);

public:
	Application();
	~Application();

	void run();
};
