#include "Application.h"

/*
*  == file layout ==
*
* -1 byte -> version number
* -32 bytes -> pw hash (sha256)
* -4 bytes -> number of items (unsiged int)
* -...bytes -> private data
*/

int main() {
	Application app;
	app.run();

	return 0;
}