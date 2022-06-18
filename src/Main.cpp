#include "Application.h"
#include <iostream>
using namespace std;
/*
*  == file layout ==
*
* -1 byte -> version number
* -32 bytes -> pw hash (sha256)
* -4 bytes -> number of items (unsiged int)
* -...bytes -> private data
*/

int main() {
	//char abc[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789.,;:-_#+*~<>!%&/(){}[]=?ßẞ ";

	Application app;
	app.run();

	return 0;
}