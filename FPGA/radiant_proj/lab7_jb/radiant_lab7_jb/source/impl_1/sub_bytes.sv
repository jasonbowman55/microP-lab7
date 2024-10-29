// Jason Bowman
// jbowman@hmc.edu
// CREATED: 10-28-24
// This creates the 4x4 byte array called aes_state

//`include "AESTypes.svh"

module sub_bytes(
	input logic [127:0] round_key_done,
	output logic [0:3][0:3][7:0] aes_state
	);
	
    assign aes_state[0][0] = round_key_done[127:120]; // S00
    assign aes_state[1][0] = round_key_done[119:112]; // S01
    assign aes_state[2][0] = round_key_done[111:104]; // S02
    assign aes_state[3][0] = round_key_done[103:96];  // S03

    assign aes_state[0][1] = round_key_done[95:88];   // S10
    assign aes_state[1][1] = round_key_done[87:80];   // S11
    assign aes_state[2][1] = round_key_done[79:72];   // S12
    assign aes_state[3][1] = round_key_done[71:64];   // S13

    assign aes_state[0][2] = round_key_done[63:56];   // S20
    assign aes_state[1][2] = round_key_done[55:48];   // S21
    assign aes_state[2][2] = round_key_done[47:40];   // S22
    assign aes_state[3][2] = round_key_done[39:32];   // S23

    assign aes_state[0][3] = round_key_done[31:24];   // S30
    assign aes_state[1][3] = round_key_done[23:16];   // S31
    assign aes_state[2][3] = round_key_done[15:8];    // S32
    assign aes_state[3][3] = round_key_done[7:0];     // S33
endmodule