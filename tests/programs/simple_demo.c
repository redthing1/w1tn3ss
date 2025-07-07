/*
 * simple demo program for w1script testing
 * performs basic operations with limited output
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// simple function to add two numbers
int add(int a, int b) {
    return a + b;
}

// simple function to multiply two numbers
int multiply(int a, int b) {
    return a * b;
}

// function that allocates and frees memory
void memory_test() {
    char* buffer = malloc(64);
    if (buffer) {
        strcpy(buffer, "hello world");
        printf("allocated buffer: %s\n", buffer);
        free(buffer);
    }
}

// function with a simple loop
void loop_test() {
    int sum = 0;
    for (int i = 1; i <= 5; i++) {
        sum += i;
    }
    printf("sum 1-5: %d\n", sum);
}

int main() {
    printf("simple demo starting\n");
    
    // basic arithmetic
    int result1 = add(10, 20);
    int result2 = multiply(5, 6);
    printf("add(10, 20) = %d\n", result1);
    printf("multiply(5, 6) = %d\n", result2);
    
    // memory operations
    memory_test();
    
    // loop operations
    loop_test();
    
    printf("simple demo finished\n");
    return 0;
}