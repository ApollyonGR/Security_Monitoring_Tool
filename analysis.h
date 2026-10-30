#ifndef ANALYSIS_H
#define ANALYSIS_H

#include "security_event.h"

int countEventsByType(SecurityEvent events[], int totalEvents, const char *eventType);

int countFailedLogins(SecurityEvent events[], int totalEvents);
int countPortScanEvents(SecurityEvent events[], int totalEvents);
int countUAEvents(SecurityEvent events[], int totalEvents);
int countMalwareEvents(SecurityEvent events[], int totalEvents);
int countPhishingEvents(SecurityEvent events[], int totalEvents);
int countCriticalEvents(SecurityEvent events[], int totalEvents);
int findHighestSeverity(SecurityEvent events[], int totalEvents);
int countHighestSeverity(SecurityEvent events[], int totalEvents);

void displaySummary(SecurityEvent events[], int totalEvents);

#endif