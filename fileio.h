#ifndef FILEIO_H
#define FILEIO_H

#include "security_event.h"

int loadEvents(const char *filename, SecurityEvent **eventsPtr, int *capacityPtr);
int generateReport( const char *filename, SecurityEvent events[], int count);

#endif