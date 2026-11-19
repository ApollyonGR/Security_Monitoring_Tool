#include <stdio.h>
#include <stdlib.h>
#include "security_event.h"


int loadEvents(const char *filename, SecurityEvent **eventsPtr, int *capacityPtr){ 
    
    // Error handling
    if (filename == NULL || eventsPtr == NULL || capacityPtr == NULL){
        return -1; }
    // Error handling
    FILE *fptr = fopen(filename, "r");
    if (fptr == NULL){
        printf("The file failed to open.\n");
        return -1; } 

    // Create local pointer to point to dynamic array on the heap
    SecurityEvent *arr = NULL;
    int count = 0; 
    int cap = 0;

    while (1) {
        // FIRST CONDITIONAL: If the number of events meets the array capacity, reallocate memory
        if (count == cap){ 
            int newCap = (cap == 0) ? 16 : cap * 2; // If cap == 0; newCap = 16, else newCap = (cap * 2)
            
            // Declares a "SecurityEvent *" pointer to hold the result of realloc()
            // Realloc requests however many bytes of memory based on the result of newCap (16, 32, 64, etc.) * sizeof(*tmp)
            SecurityEvent *tmp = realloc(arr, (size_t)newCap * sizeof(*tmp));
            
            // Error handling
            if (tmp == NULL) {
                printf("Memory allocation failed while loading events\n");
                free (arr);
                fclose(fptr);
                return -1;
            }

            arr = tmp; // Safely assigns the memory address returned in tmp to arr, so arr points to the newly resized heap block
            cap = newCap; // Updates the local cap variable to track the new capacity
        }

        int lines = fscanf(fptr, "%24s %15s %9s %d",
                        arr[count].eventType,
                        arr[count].eventSource,
                        arr[count].accountName,
                        &arr[count].severity);
        
        if (lines != 4){
            break; // Reached EOF or malformed line
        }

        arr[count].id = count+1;
        count++;
    }

    fclose(fptr);
    *eventsPtr = arr; // Passes the reallocated heap array's memory address to main()'s "events" pointer
    *capacityPtr = cap; // Does the same for the int "capacity" in main 
    return count; // returns the total number of events loaded for use in main.c
}

int generateReport(const char *filename, SecurityEvent events[], int count){
    FILE *fptr = fopen(filename, "w");

    if (fptr == NULL){
        printf("The file failed to open.\n");
        return -1;
    }

    displayEvents(fptr, events, count);
    fclose(fptr);
    return 0;
}