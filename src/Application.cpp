#include "Application.h"

Application::Application() {
	item_count = 0;
	length_of_one_item = login_length + username_length + email_length + password_length + additional_length;

	pw = new uint8_t[1000];
	pw_hash = nullptr;

	encrypted_private_data = nullptr;
	decrypted_private_data = nullptr;

	aes = AES(AESKeyLength::AES_256);
}

Application::~Application() {
	handle_exit();
}

void Application::handle_exit() {
	save();
	overwrite_ram();
}

void Application::overwrite_ram() {
	if (pw != nullptr) {
		memset(pw, 0, 1000);
		delete[] pw;
		pw = nullptr;
	}

	if (decrypted_private_data != nullptr) {
		memset(decrypted_private_data, 0, item_count * length_of_one_item);
		delete[] decrypted_private_data;
		decrypted_private_data = nullptr;
	}

	std::cout << "RAM successfully overwritten!" << std::endl;
}

bool Application::save_to_file(std::string file_name, const char output_data[], const int data_size) {
	if (file_name == "")
		return false;

	auto myfile = std::fstream(file_name, std::ios::out | std::ios::binary);
	myfile.write((char*)output_data, data_size);
	myfile.close();

	return true;
}

bool Application::read_from_file(std::string file_name, std::vector<char>& input_data) {
	if (file_name == "")
		return false;

	std::ifstream input(file_name, std::ios::binary);
	if (!input.good())
		return false;

	input_data = std::vector<char>((std::istreambuf_iterator<char>(input)), (std::istreambuf_iterator<char>()));
	input.close();
	return true;
}

/*
0: Black		   8: Grey
1: Blue			   9: Bright blue
2: Green		   A: Brigth green
3: Cyan			   B: Bright cyan
4: Red			   C: Bright red
5: Purple		   D: Pink
6: Dark Yellow	   E: Yellow
7: White		   F: Bright white
*/
void Application::set_color(int color) {
	SetConsoleTextAttribute(hStdOut, color);
}

void Application::update_lists() {
	login_places.clear();
	usernames.clear();
	emails.clear();
	passwords.clear();
	additionals.clear();

	for (long i = 0; i < item_count; i++) {
		login_places.push_back((char*)&(decrypted_private_data[i * length_of_one_item]));
		usernames.push_back((char*)&(decrypted_private_data[i * length_of_one_item + login_length]));
		emails.push_back((char*)&(decrypted_private_data[i * length_of_one_item + login_length + username_length]));
		passwords.push_back((char*)&(decrypted_private_data[i * length_of_one_item + login_length + username_length + email_length]));
		additionals.push_back((char*)&(decrypted_private_data[i * length_of_one_item + login_length + username_length + email_length + password_length]));
	}
}

void Application::add_item(char* login_place, char* username, char* email, char* password, char* additional) {
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

	update_lists();

	sort_list();

	save();
}

void Application::shrink_data_to_lists() {
	uint8_t* new_list = new uint8_t[login_places.size() * length_of_one_item];

	for (int i = 0; i < login_places.size(); i++) {
		memcpy(&(new_list[i * length_of_one_item]), login_places[i], login_length);
		memcpy(&(new_list[i * length_of_one_item + login_length]), usernames[i], username_length);
		memcpy(&(new_list[i * length_of_one_item + login_length + username_length]), emails[i], email_length);
		memcpy(&(new_list[i * length_of_one_item + login_length + username_length + email_length]), passwords[i], password_length);
		memcpy(&(new_list[i * length_of_one_item + login_length + username_length + email_length + password_length]), additionals[i], additional_length);
	}

	memset(decrypted_private_data, 0, item_count * length_of_one_item);
	delete[] decrypted_private_data;
	decrypted_private_data = new_list;

	item_count = login_places.size();

	update_lists();
}

uint8_t* Application::get_hash(uint8_t* data, size_t size) {
	SHA256 sha;
	sha.update(data, size);
	return sha.digest();
}

void Application::save() {
	if (decrypted_private_data == nullptr || item_count <= 0)
		return;

	//=== compress decrypted data ===

	//calc size for compressed save buffer
	size_t save_size = item_count * 5;
	for (int item_offset = 0; item_offset < item_count; item_offset++) {
		for (int offset = 0; offset < 5; offset++) {
			save_size += strlen((char*)&decrypted_private_data[item_offset * length_of_one_item + offset * 256]);
		}
	}
	//append to size to be multiple of 16 for AES
	save_size = (1.0f - ((double(save_size) / 16) - int(double(save_size) / 16))) * 16 + save_size;

	//create and fill compressed save buffer
	uint8_t* compressed_data = new uint8_t[save_size];
	memset(compressed_data, 0, save_size);
	size_t save_offset = 0;
	for (int item_offset = 0; item_offset < item_count; item_offset++) {
		for (int offset = 0; offset < 5; offset++) {
			int str_len = strlen((char*)&decrypted_private_data[item_offset * length_of_one_item + offset * 256]);
			compressed_data[save_offset] = str_len;
			save_offset++;
			memcpy(&compressed_data[save_offset], &decrypted_private_data[item_offset * length_of_one_item + offset * 256], str_len);
			save_offset += str_len;
		}
	}

	//encrypt and save
	uint8_t* temp = encrypted_private_data;
	encrypted_private_data = (uint8_t*)aes.EncryptECB(compressed_data, save_size, pw);
	uint8_t* save_data = new uint8_t[37 + save_size];
	save_data[0] = 1;//version
	memcpy(&(save_data[1]), pw_hash, 32);//pw hash
	memcpy(&(save_data[33]), &item_count, sizeof(int));//item count
	memcpy(&(save_data[37]), encrypted_private_data, save_size);//encrypted data
	save_to_file("encrypted.pw", (char*)save_data, 37 + save_size);
	delete[] encrypted_private_data;
	encrypted_private_data = temp;
	delete[] save_data;
}

void Application::clear_input_buffer() {
	std::cin.clear();
	std::cin.ignore(INT_MAX, '\n');
}

bool Application::is_string_number(std::string str) {
	for (int i = 0; i < str.length(); i++) {
		if (str[i] < '0' || str[i]>'9' || str[i] == '-') {
			return false;
		}
	}
	return true;
}

int Application::get_number_in_abc(char* c) {
	for (int i = 0; i < 62; i++) {
		if (abc_order[i] == *c)
			return i + 1;
	}
	return 100;
}

bool Application::string_later(char* str, char* compare_str) {
	int i = 0;
	while (true) {
		//if end of string
		if (str[i] == 0)
			return false;

		//if end of compare_str
		if (compare_str[i] == 0)
			return true;

		if (get_number_in_abc(&(str[i])) < get_number_in_abc(&(compare_str[i]))) {
			return false;
		}
		else if (get_number_in_abc(&(str[i])) > get_number_in_abc(&(compare_str[i]))) {
			return true;
		}

		i++;
	}
}

void Application::sort_list() {
	if (item_count < 2)
		return;

	int* index_list = new int[item_count];
	for (int i = 0; i < item_count; i++) {
		index_list[i] = i;
	}

	//sort alphabetically
	for (int N = item_count - 1; N > 0; N--) {
		for (int n = 0; n < N; n++) {
			if (string_later(login_places[index_list[n]], login_places[index_list[n + 1]])) {
				int temp = index_list[n];
				index_list[n] = index_list[n + 1];
				index_list[n + 1] = temp;
			}
		}
	}

	//rearange strings in list
	uint8_t* new_list = new uint8_t[item_count * length_of_one_item];
	memset(new_list, 0, item_count * length_of_one_item);//unnötig aber ich bin paranoid dass da noch etwas drinnen bleibt
	for (int i = 0; i < item_count; i++) {
		memcpy(&(new_list[i * length_of_one_item]), &(decrypted_private_data[index_list[i] * length_of_one_item]), length_of_one_item);
	}
	memset(decrypted_private_data, 0, item_count * length_of_one_item);
	delete[] decrypted_private_data;
	decrypted_private_data = new_list;

	update_lists();

	delete[] index_list;

	std::cout << "successfully sorted list!" << std::endl;
}

void Application::print_help() {
	std::cout << " === HELP MENU ===\n"
		<< "    - commands: -\n"
		<< " help - shows this menu\n"
		<< " exit - cleans up data and exits\n"
		<< " cls - clears console\n"
		<< " sort - sort list alphabetically\n"
		<< " get - print data from selected item\n"
		<< " short - prints list of all item names\n"
		<< " long - prints detailed list of all items\n"
		<< " add - add an item to list\n"
		<< " remove - remove item by number\n"
		<< " edit - edit item by number\n"
		<< " password - prints current password\n"
		<< " new_pw - set new password\n"
		<< " update - check github for latest version\n"
		<< "============================="
		<< std::endl;
}

void Application::print_short_list() {
	std::cout << "-----\n";
	for (int i = 0; i < item_count; i++) {
		std::cout << (i + 1) << ":" << login_places[i] << "\n";
	}
	std::cout << "-----\n";
}

void Application::run() {
	//create file if it doesnt exist already
	std::ifstream input("encrypted.pw", std::ios::binary);
	if (!input.good()) {
		std::cout << "ERROR: file 'encrypted.pw' is missing" << std::endl;

		std::cout << "Create new file? (y/n):";
		char in;
		std::cin >> in;
		if (int(in) == 121 || int(in) == 89) {
			system("cls");
			std::string new_pw;
			clear_input_buffer();
			std::cout << "set password for new file:";
			std::getline(std::cin, new_pw);
			memset(pw, 0, 1000);
			for (int i = 0; i < new_pw.length() && i < 999; i++) {
				pw[i] = new_pw[i];
			}
			std::cout << "password set to:" << pw << std::endl;

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
			return;
		}
	}
	input.close();

	//load data from file
	std::vector<char> file_data;
	if (!read_from_file("encrypted.pw", file_data)) {
		std::cout << "ERROR: couldnt read from file" << std::endl;
		std::cin.get();
		return;
	}

	if (file_data.size() < 37) {
		std::cout << "Datei ist kaputt" << std::endl;;
		return;
	}
	system("cls");

	//check version
	if (file_data[0] != 1) {
		system("cls");
		std::cout << "ERROR: outdated file-version!" << std::endl;
		std::cin.get();
		return;
	}

	//copy data from file
	pw_hash = (uint8_t*)&(file_data[1]);//pw hash
	memcpy(&item_count, (unsigned int*)&(file_data[33]), 4);//item count
	if (item_count > 0) {
		encrypted_private_data = (uint8_t*)&(file_data[37]);//encrypted data
	}

	int incorrect_pw_count = 0;
	bool correct_pw = false;
	while (!correct_pw)
	{
		std::string in_pw;
		std::cout << "input password to file:";
		std::getline(std::cin, in_pw);
		memset(pw, 0, 1000);
		for (int i = 0; i < in_pw.length() && i < 999; i++) {
			pw[i] = in_pw[i];
		}

		uint8_t* sha_out = get_hash((uint8_t*)pw, 1000);
		correct_pw = true;
		for (int i = 0; i < 32; i++) {
			if (sha_out[i] != pw_hash[i]) {
				correct_pw = false;
				incorrect_pw_count++;
				if (incorrect_pw_count >= MAX_TRIES) {
					delete[] sha_out;
					return;
				}
				system("cls");
				std::cout << "wrong password! (wait " << ADDITIONAL_WAIT_TIME * incorrect_pw_count / 1000 << " seconds to try again)" << std::endl;
				std::this_thread::sleep_for(std::chrono::milliseconds(ADDITIONAL_WAIT_TIME * incorrect_pw_count));
				break;
			}
		}
		delete[] sha_out;
	}

	system("cls");
	std::cout << "type 'help' for help-menu" << std::endl;

	//decrypt data
	if (encrypted_private_data != nullptr) {
		size_t data_size = file_data.size() - 37;
		decrypted_private_data = (uint8_t*)aes.DecryptECB(encrypted_private_data, data_size, pw);

		//uncompress decrypted data
		uint8_t* decompressed_data = new uint8_t[item_count * length_of_one_item];
		memset(decompressed_data, 0, item_count * length_of_one_item);
		size_t off = 0;
		for (int item_offset = 0; item_offset < item_count; item_offset++) {
			for (int offset = 0; offset < 5; offset++) {
				memcpy(&decompressed_data[item_offset * length_of_one_item + offset * 256], &decrypted_private_data[off + 1], decrypted_private_data[off]);
				off += 1 + decrypted_private_data[off];
			}
		}
		delete[] decrypted_private_data;
		decrypted_private_data = decompressed_data;
	}

	//create lists
	update_lists();

	std::string login_place;
	std::string username;
	std::string email;
	std::string password;
	std::string additional;

	//wait for command input:
	std::string command;
	while (true) {
		std::cout << ">";
		std::cin >> command;

		clear_input_buffer();
		if (command == "help") {
			print_help();
		}
		else if (command == "debug") {
			break;
		}
		else if (command == "exit") {
			break;
		}
		else if (command == "cls") {
			system("cls");
		}
		else if (command == "sort") {
			sort_list();
		}
		else if (command == "short") {
			print_short_list();
		}
		else if (command == "long") {
			for (int i = 0; i < item_count; i++) {
				std::cout << "----- " << (i + 1) << ": " << login_places[i] << " -----"
					<< "\nusername: " << usernames[i]
					<< "\nemail: " << emails[i]
					<< "\npassword: " << passwords[i]
					<< "\nadditional: " << additionals[i]
					<< "\n\n";
			}
		}
		else if (command == "add") {
			std::cout << "add new item? (y/n): ";
			char in;
			std::cin >> in;
			if (int(in) == 121 || int(in) == 89) {
			}
			else {
				continue;
			}

			clear_input_buffer();
			system("cls");
			std::cout << "login place name: ";
			std::getline(std::cin, login_place);

			std::cout << "username: ";
			std::getline(std::cin, username);

			std::cout << "email: ";
			std::getline(std::cin, email);

			std::cout << "password: ";
			std::getline(std::cin, password);

			std::cout << "additional text: ";
			std::getline(std::cin, additional);

			add_item((char*)&(login_place[0]), (char*)&(username[0]), (char*)&(email[0]), (char*)&(password[0]), (char*)&(additional[0]));

			std::cout << "-- successfully added item --" << std::endl;
		}
		else if (command == "get") {
			print_short_list();

			std::cout << "input number of login place (-1 to exit): ";
			std::string input;
			std::cin >> input;
			if (!is_string_number(input)) {
				std::cout << "input must be a positive number" << std::endl;
				continue;
			}
			int number = stoi(input);

			if (number < 1 || number > item_count) {
				std::cout << "number out of range" << std::endl;
				continue;
			}

			number--;
			std::cout << "\n+----- " << (number + 1) << ": " << login_places[number] << " --------------"
				<< "\n| username: " << usernames[number]
				<< "\n| email: " << emails[number]
				<< "\n| password: " << passwords[number]
				<< "\n| additional: " << additionals[number]
				<< "\n+------------------------------\n";
		}
		else if (command == "remove") {
			print_short_list();

			std::cout << "input number of login place (-1 to exit): ";
			std::string input;
			std::cin >> input;
			if (!is_string_number(input)) {
				std::cout << "input must be a positive number" << std::endl;
				continue;
			}
			int number = stoi(input);

			if (number < 1 || number > item_count) {
				std::cout << "number out of range" << std::endl;
				continue;
			}

			login_places.erase(login_places.begin() + (number - 1));
			usernames.erase(usernames.begin() + (number - 1));
			emails.erase(emails.begin() + (number - 1));
			passwords.erase(passwords.begin() + (number - 1));
			additionals.erase(additionals.begin() + (number - 1));

			shrink_data_to_lists();

			save();
			std::cout << "removed number " << number << std::endl;
		}
		else if (command == "edit") {
			std::cout << "edit a item? (y/n): ";
			char in;
			std::cin >> in;
			if (int(in) == 121 || int(in) == 89) {
			}
			else {
				continue;
			}

			print_short_list();

			clear_input_buffer();
			std::cout << "input number of login place (-1 to exit): ";
			std::string input;
			std::cin >> input;
			if (!is_string_number(input)) {
				std::cout << "input must be a positive number" << std::endl;
				continue;
			}
			int number = stoi(input);

			if (number < 1 || number > item_count) {
				std::cout << "number out of range" << std::endl;
				continue;
			}
			number--;

			system("cls");
			clear_input_buffer();
			std::cout << "old login place name: " << login_places[number]
				<< "\nnew login place name: ";
			std::getline(std::cin, login_place);

			std::cout << "\nold username: " << usernames[number]
				<< "\nnew username: ";
			std::getline(std::cin, username);

			std::cout << "\nold email: " << emails[number]
				<< "\nnew email: ";
			std::getline(std::cin, email);

			std::cout << "\nold password: " << passwords[number]
				<< "\nnew password: ";
			std::getline(std::cin, password);

			std::cout << "\nold additional: " << additionals[number]
				<< "\nnew additional: ";
			std::getline(std::cin, additional);

			system("cls");
			std::cout << "=== NEW DATA ==="
				<< "\nlogin place: " << login_place
				<< "\nusername: " << username
				<< "\nemail: " << email
				<< "\npassword: " << password
				<< "\nadditional: " << additional
				<< "\n================\n" << std::endl;

			std::cout << "save changes? (y/n): ";
			std::cin >> in;
			if (int(in) == 121 || int(in) == 89) {
				memset(&(decrypted_private_data[number * length_of_one_item]), 0, length_of_one_item);

				//add data to list
				memcpy(&(decrypted_private_data[number * length_of_one_item]), &(login_place[0]), login_place.length() >= login_length ? login_length - 1 : login_place.length());
				memcpy(&(decrypted_private_data[number * length_of_one_item + login_length]), &(username[0]), username.length() >= username_length ? username_length - 1 : username.length());
				memcpy(&(decrypted_private_data[number * length_of_one_item + login_length + username_length]), &(email[0]), email.length() >= email_length ? email_length - 1 : email.length());
				memcpy(&(decrypted_private_data[number * length_of_one_item + login_length + username_length + email_length]), &(password[0]), password.length() >= password_length ? password_length - 1 : password.length());
				memcpy(&(decrypted_private_data[number * length_of_one_item + login_length + username_length + email_length + password_length]), &(additional[0]), additional.length() >= additional_length ? additional_length - 1 : additional.length());
			}
			else {
				std::cout << "discarded!" << std::endl;
				continue;
			}

			save();
			std::cout << "saved changes!" << std::endl;
		}
		else if (command == "password") {
			std::cout << "current password: " << pw << std::endl;
		}
		else if (command == "new_pw") {
			std::cout << "change password? (y/n): ";
			char in;
			std::cin >> in;
			if (int(in) == 121 || int(in) == 89) {
			}
			else {
				system("cls");
				continue;
			}

			std::string new_pw;
			clear_input_buffer();
			std::cout << "input new password: ";
			std::getline(std::cin, new_pw);

			memset(pw, 0, 1000);
			for (int i = 0; i < new_pw.length() && i < 999; i++) {
				pw[i] = new_pw[i];
			}

			pw_hash = get_hash(pw, 1000);
			save();
			std::cout << "password set to: " << pw << std::endl;
		}
		else if (command == "update") {
			std::cout << "check latest version on https://github.com/BirnB4um/PasswordManager" << std::endl;
		}
		else {
			std::cout << "unknown command." << std::endl;
		}
	}
}