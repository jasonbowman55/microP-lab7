// Jason Bowman
// jbowman@hmc.edu
// CREATED: 10-28-24
// This module calles the sbox function (copied from aes_starter.sv) which applies the necessary bit substitution for AES

module sub_bytes(
	input logic [127:0] round_key_done,
	output logic [127:0] sub_bytes_done);

	// assign bytes of data to be apart of the 4x4 byte array

	//assign S00 = round_key_done[7:0];
	//assign S01 = round_key_done[15:8];
	//assign S02 = round_key_done[23:16];
	//assign S03 = round_key_done[31:24];

	//assign S10 = round_key_done[39:32];
	//assign S11 = round_key_done[47:40];
	//assign S12 = round_key_done[55:48];
	//assign S13 = round_key_done[63:56];

	//assign S20 = round_key_done[71:64];
	//assign S21 = round_key_done[79:72];
	//assign S22 = round_key_done[87:80];
	//assign S23 = round_key_done[95:88];

	//assign S30 = round_key_done[103:96];
	//assign S31 = round_key_done[111:104];
	//assign S32 = round_key_done[119:112];
	//assign S33 = round_key_done[127:120];


	sbox sbox00(.a(round_key_done[7:0]),    .y(sub_bytes_done[7:0]));    // S00
    sbox sbox01(.a(round_key_done[15:8]),   .y(sub_bytes_done[15:8]));   // S01
    sbox sbox02(.a(round_key_done[23:16]),  .y(sub_bytes_done[23:16]));  // S02
    sbox sbox03(.a(round_key_done[31:24]),  .y(sub_bytes_done[31:24]));  // S03

    sbox sbox10(.a(round_key_done[39:32]),  .y(sub_bytes_done[39:32]));  // S10
    sbox sbox11(.a(round_key_done[47:40]),  .y(sub_bytes_done[47:40]));  // S11
    sbox sbox12(.a(round_key_done[55:48]),  .y(sub_bytes_done[55:48]));  // S12
    sbox sbox13(.a(round_key_done[63:56]),  .y(sub_bytes_done[63:56]));  // S13

    sbox sbox20(.a(round_key_done[71:64]),  .y(sub_bytes_done[71:64]));  // S20
    sbox sbox21(.a(round_key_done[79:72]),  .y(sub_bytes_done[79:72]));  // S21
    sbox sbox22(.a(round_key_done[87:80]),  .y(sub_bytes_done[87:80]));  // S22
    sbox sbox23(.a(round_key_done[95:88]),  .y(sub_bytes_done[95:88]));  // S23

    sbox sbox30(.a(round_key_done[103:96]), .y(sub_bytes_done[103:96])); // S30
    sbox sbox31(.a(round_key_done[111:104]), .y(sub_bytes_done[111:104])); // S31
    sbox sbox32(.a(round_key_done[119:112]), .y(sub_bytes_done[119:112])); // S32
    sbox sbox33(.a(round_key_done[127:120]), .y(sub_bytes_done[127:120])); // S33
endmodule


module sbox(input  logic [7:0] a,
            output logic [7:0] y);
            
  // sbox implemented as a ROM
  // This module is combinational and will be inferred using LUTs (logic cells)
  logic [7:0] sbox[0:255];

  initial   $readmemh("sbox.txt", sbox);
  assign y = sbox[a];
endmodule

/////////////////////////////////////////////
// sbox
//   Infamous AES byte substitutions with magic numbers
//   Synchronous version which is mapped to embedded block RAMs (EBR)
//   Section 5.1.1, Figure 7
/////////////////////////////////////////////
module sbox_sync(
	input		logic [7:0] a,
	input	 	logic 			clk,
	output 	logic [7:0] y);
            
  // sbox implemented as a ROM
  // This module is synchronous and will be inferred using BRAMs (Block RAMs)
  logic [7:0] sbox [0:255];

  initial   $readmemh("sbox.txt", sbox);
	
	// Synchronous version
	always_ff @(posedge clk) begin
		y <= sbox[a];
	end
endmodule
