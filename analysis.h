#ifndef ANALYSIS_H
#define ANALYSIS_H

#include "security_event.h"

int countEventsByParameter(SecurityEvent events[], int totalEvents, const char *eventType);

int countCriticalEvents(SecurityEvent events[], int totalEvents);
int findHighestSeverity(SecurityEvent events[], int totalEvents);
int countHighestSeverity(SecurityEvent events[], int totalEvents);

int handleAnalysisMenu(SecurityEvent events[], int totalEvents);

int AnalysisMenu(void);

#endif