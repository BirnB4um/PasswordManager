#include "Application.h"
#include <iostream>
using namespace std;

/*
*  == save-file layout ==
*
* -1 byte -> version number
* -32 bytes -> pw hash
* -4 bytes -> number of items (unsiged int)
* -...bytes -> encrypted private data
*/

Application app;
BOOL WINAPI ConsoleHandlerRoutine(DWORD dwCtrlType) {
	/*
	CTRL_SHUTDOWN_EVENT
	CTRL_LOGOFF_EVENT
	CTRL_C_EVENT
	CTRL_CLOSE_EVENT
	*/
	if (CTRL_C_EVENT == dwCtrlType) {
		app.handle_exit();
		return FALSE;
	}

	if (CTRL_CLOSE_EVENT == dwCtrlType || CTRL_SHUTDOWN_EVENT == dwCtrlType) {
		app.handle_exit();
		return TRUE;
	}
	return FALSE;
}

int main() {
	SetConsoleTitleA("Password Manager - version 0.1");

	if (FALSE == SetConsoleCtrlHandler(ConsoleHandlerRoutine, TRUE)) {
		std::cout << "ERROR: cannot register handler. RAM will only be overwritten when programm is closed via 'exit' command!" << std::endl;
	}

	app.run();

	return 0;
}