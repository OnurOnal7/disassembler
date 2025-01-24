#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

// Structure to store label information
typedef struct Label {
    uint32_t address;
    char name[16];
    struct Label *next;
} Label;

Label *label_head = NULL;
int label_counter = 1;

// Function to add a new label
const char* add_label(uint32_t address) {
    Label *new_label = (Label*) malloc(sizeof(Label));
    if (!new_label) {
        perror("Failed to allocate memory for label");
        exit(1);
    }
    new_label->address = address;
    snprintf(new_label->name, sizeof(new_label->name), "label%d", label_counter++);
    new_label->next = NULL;

    if (label_head == NULL) {
        label_head = new_label;
    } 
    else {
        Label *current = label_head;
        while (current->next != NULL) {
            current = current->next;
        }
        current->next = new_label;
    }
    return new_label->name;
}

// Function to retrieve a label by address
const char* get_label(uint32_t address) {
    Label *current = label_head;
    while (current) {
        if (current->address == address) {
            return current->name;
        }
        current = current->next;
    }
    return NULL;
}

// Function to sign-extend a value with 'bits' bits
int32_t sign_extend(uint32_t value, int bits) {
    if (value & (1U << (bits - 1))) {
        return (int32_t)(value | (~0U << bits));
    }
    return (int32_t)value;
}

// Function to map condition codes to mnemonics
const char* get_cond_mnemonic(uint32_t cond) {
    switch (cond) {
        case 0x0: return "EQ";
        case 0x1: return "NE";
        case 0x2: return "HS";
        case 0x3: return "LO";
        case 0x4: return "MI";
        case 0x5: return "PL";
        case 0x6: return "VS";
        case 0x7: return "VC";
        case 0x8: return "HI";
        case 0x9: return "LS";
        case 0xA: return "GE";
        case 0xB: return "LT";
        case 0xC: return "GT";
        case 0xD: return "LE";
        default: return "UNKNOWN";
    }  
}

// Function to print labels before the instruction if present
void print_label(uint32_t current_address) {
    const char* label = get_label(current_address);
    if (label) {
        printf("%s:\n", label);
    }
}

// Function to decode and disassemble a single instruction
void decode_instruction(uint32_t instruction, uint32_t current_address) {
    // Common fields
    uint32_t Rd, Rn, Rm, Rt;
    int32_t imm;
    uint32_t shamt;
    const char* cond_mnemonic;

    // Extract possible opcode fields
    uint32_t opcode_R = (instruction >> 21) & 0x7FF;   // 11 bits
    uint32_t opcode_I = (instruction >> 22) & 0x3FF;   // 10 bits
    uint32_t opcode_B = (instruction >> 26) & 0x3F;    // 6 bits
    uint32_t opcode_CB = (instruction >> 24) & 0xFF;   // 8 bits
    uint32_t opcode_D = (instruction >> 21) & 0x7FF;   // 11 bits

    // Handle R-type instructions and special instructions
    switch (opcode_R) {
        case 0b10001011000: { // ADD
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            Rm = (instruction >> 16) & 0x1F;
            printf("ADD X%d, X%d, X%d\n", Rd, Rn, Rm);
            return;
        }
        case 0b10001010000: { // AND
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            Rm = (instruction >> 16) & 0x1F;
            printf("AND X%d, X%d, X%d\n", Rd, Rn, Rm);
            return;
        }
        case 0b11010110000: { // BR
            Rn = (instruction >> 5) & 0x1F;
            printf("BR X%d\n", Rn);
            return;
        }
        case 0b11001010000: { // EOR
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            Rm = (instruction >> 16) & 0x1F;
            printf("EOR X%d, X%d, X%d\n", Rd, Rn, Rm);
            return;
        }
        case 0b11010011011: { // LSL
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            shamt = (instruction >> 10) & 0x3F; 
            printf("LSL X%d, X%d, #%d\n", Rd, Rn, shamt);
            return;
        }
        case 0b11010011010: { // LSR
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            shamt = (instruction >> 10) & 0x3F; 
            printf("LSR X%d, X%d, #%d\n", Rd, Rn, shamt);
            return;
        }
        case 0b10101010000: { // ORR
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            Rm = (instruction >> 16) & 0x1F;
            printf("ORR X%d, X%d, X%d\n", Rd, Rn, Rm);
            return;
        }
        case 0b11001011000: { // SUB
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            Rm = (instruction >> 16) & 0x1F;
            printf("SUB X%d, X%d, X%d\n", Rd, Rn, Rm);
            return;
        }
        case 0b11101011000: { // SUBS
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            Rm = (instruction >> 16) & 0x1F;
            printf("SUBS X%d, X%d, X%d\n", Rd, Rn, Rm);
            return;
        }
        case 0b10011011000: { // MUL
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            Rm = (instruction >> 16) & 0x1F;
            printf("MUL X%d, X%d, X%d\n", Rd, Rn, Rm);
            return;
        }
        case 0b11111111101: { // PRNT
            Rd = (instruction >> 0) & 0x1F;
            printf("PRNT X%d\n", Rd);
            return;
        }
        case 0b11111111100: { // PRNL
            printf("PRNL\n");
            return;
        }
        case 0b11111111110: { // DUMP
            printf("DUMP\n");
            return;
        }
        case 0b11111111111: { // HALT
            printf("HALT\n");
            return;
        }
        default:
            break;
    }

    // Handle I-type instructions
    switch (opcode_I) {
        case 0b1001000100: { // ADDI
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            imm = sign_extend((instruction >> 10) & 0xFFF, 12);
            printf("ADDI X%d, X%d, #%d\n", Rd, Rn, imm);
            return;
        }
        case 0b1001001000: { // ANDI
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            imm = sign_extend((instruction >> 10) & 0xFFF, 12);
            printf("ANDI X%d, X%d, #%d\n", Rd, Rn, imm);
            return;
        }
        case 0b1101001000: { // EORI
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            imm = sign_extend((instruction >> 10) & 0xFFF, 12);
            printf("EORI X%d, X%d, #%d\n", Rd, Rn, imm);
            return;
        }
        case 0b1011001000: { // ORRI
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            imm = sign_extend((instruction >> 10) & 0xFFF, 12);
            printf("ORRI X%d, X%d, #%d\n", Rd, Rn, imm);
            return;
        }
        case 0b1101000100: { // SUBI
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            imm = sign_extend((instruction >> 10) & 0xFFF, 12);
            printf("SUBI X%d, X%d, #%d\n", Rd, Rn, imm);
            return;
        }
        case 0b1111000100: { // SUBIS
            Rd = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            imm = sign_extend((instruction >> 10) & 0xFFF, 12);
            printf("SUBIS X%d, X%d, #%d\n", Rd, Rn, imm);
            return;
        }
        default:
            break;
    }

    // Handle D-type instructions
    switch (opcode_D) {
        case 0b11111000010: { // LDUR
            Rt = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            imm = sign_extend((instruction >> 10) & 0xFFF, 12);
            printf("LDUR X%d, [X%d, #%d]\n", Rt, Rn, imm / 4);
            return;
        }
        case 0b11111000000: { // STUR
            Rt = (instruction >> 0) & 0x1F;
            Rn = (instruction >> 5) & 0x1F;
            imm = sign_extend((instruction >> 10) & 0xFFF, 12);
            printf("STUR X%d, [X%d, #%d]\n", Rt, Rn, imm / 4);
            return;
        }
        default:
            break;
    }

    // Handle B-type instructions
    switch (opcode_B) {
        case 0b000101: { // B
            int32_t imm26 = sign_extend(instruction & 0x3FFFFFF, 26) << 2;
            uint32_t target_address = current_address + imm26;
            const char* label = get_label(target_address);
            if (!label) {
                label = add_label(target_address);
            }
            printf("B %s\n", label);
            return;
        }
        case 0b100101: { // BL
            int32_t imm26 = sign_extend(instruction & 0x3FFFFFF, 26) << 2;
            uint32_t target_address = current_address + imm26;
            const char* label = get_label(target_address);
            if (!label) {
                label = add_label(target_address);
            }
            printf("BL %s\n", label);
            return;
        }
        default:
            break;
    }

    // Handle CB-type instructions
    switch (opcode_CB) {
        case 0b01010100: { // B.cond
            Rt = (instruction >> 0) & 0x1F;
            int32_t imm19 = sign_extend((instruction >> 5) & 0x7FFFF, 19) << 2;
            uint32_t target_address = current_address + imm19;
            const char* label = get_label(target_address);
            if (!label) {
                label = add_label(target_address);
            }
            cond_mnemonic = get_cond_mnemonic(Rt);
            printf("B.%s %s\n", cond_mnemonic, label);
            return;
        }
        case 0b10110101: { // CBNZ
            Rt = (instruction >> 0) & 0x1F;
            int32_t imm19 = sign_extend((instruction >> 5) & 0x7FFFF, 19) << 2;
            uint32_t target_address = current_address + imm19;
            const char* label = get_label(target_address);
            if (!label) {
                label = add_label(target_address);
            }
            printf("CBNZ X%d, %s\n", Rt, label);
            return;
        }
        case 0b10110100: { // CBZ
            Rt = (instruction >> 0) & 0x1F;
            int32_t imm19 = sign_extend((instruction >> 5) & 0x7FFFF, 19) << 2;
            uint32_t target_address = current_address + imm19;
            const char* label = get_label(target_address);
            if (!label) {
                label = add_label(target_address);
            }
            printf("CBZ X%d, %s\n", Rt, label);
            return;
        }
        default:
            break;
    }

    // If instruction does not match any known opcode, print as .word
    printf(".word 0x%08X\n", instruction);
}

int main(int argc, char *argv[]) {
    // Ensure command-line argument usage
    if (argc < 2) {
        printf("Usage: %s <binary_file>\n", argv[0]);
    }

    // Open binary file from command-line argument
    FILE *file = fopen(argv[1], "rb");
    if (!file) {
        perror("Failed to open file");
        return 1;
    }

    uint32_t instruction;   // To store each 32-bit instruction
    uint32_t current_address = 0;   // To track the address of the instruction

    // Reset file pointer to beginning
    rewind(file);

    // Disassemble instructions
    while (fread(&instruction, sizeof(uint32_t), 1, file)) {
        instruction = ntohl(instruction); // Convert from big-endian to host endian
        print_label(current_address);
        decode_instruction(instruction, current_address);
        current_address += 4;
    }

    // Close the file
    fclose(file);

    // Free allocated labels
    Label *current = label_head;
    while (current) {
        Label *temp = current;
        current = current->next;
        free(temp);
    }

    return 0;
}