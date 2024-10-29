/////////////////////////////////////////////
// aes
//   Top level module with SPI interface and SPI core
/////////////////////////////////////////////

module aes(input  logic clk,
           input  logic sck, 
           input  logic sdi,
           output logic sdo,
           input  logic load,
           output logic done);
                    
    logic [127:0] key, plaintext, cyphertext;
            
    aes_spi spi(sck, sdi, sdo, done, key, plaintext, cyphertext);   
    aes_core core(clk, load, key, plaintext, done, cyphertext);
endmodule

/////////////////////////////////////////////
// aes_spi
//   SPI interface.  Shifts in key and plaintext
//   Captures ciphertext when done, then shifts it out
//   Tricky cases to properly change sdo on negedge clk
/////////////////////////////////////////////

module aes_spi(input  logic sck, 
               input  logic sdi,
               output logic sdo,
               input  logic done,
               output logic [127:0] key, plaintext,
               input  logic [127:0] cyphertext);

    logic         sdodelayed, wasdone;
    logic [127:0] cyphertextcaptured;
               
    // assert load
    // apply 256 sclks to shift in key and plaintext, starting with plaintext[127]
    // then deassert load, wait until done
    // then apply 128 sclks to shift out cyphertext, starting with cyphertext[127]
    // SPI mode is equivalent to cpol = 0, cpha = 0 since data is sampled on first edge and the first
    // edge is a rising edge (clock going from low in the idle state to high).
    always_ff @(posedge sck)
        if (!wasdone)  {cyphertextcaptured, plaintext, key} = {cyphertext, plaintext[126:0], key, sdi};
        else           {cyphertextcaptured, plaintext, key} = {cyphertextcaptured[126:0], plaintext, key, sdi}; 
    
    // sdo should change on the negative edge of sck
    always_ff @(negedge sck) begin
        wasdone = done;
        sdodelayed = cyphertextcaptured[126];
    end
    
    // when done is first asserted, shift out msb before clock edge
    assign sdo = (done & !wasdone) ? cyphertext[127] : sdodelayed;
endmodule

/////////////////////////////////////////////
// aes_core
//   top level AES encryption module
//   when load is asserted, takes the current key and plaintext
//   generates cyphertext and asserts done when complete 11 cycles later
// 
//   See FIPS-197 with Nk = 4, Nb = 4, Nr = 10
//
//   The key and message are 128-bit values packed into an array of 16 bytes as
//   shown below
//        [127:120] [95:88] [63:56] [31:24]     S0,0    S0,1    S0,2    S0,3
//        [119:112] [87:80] [55:48] [23:16]     S1,0    S1,1    S1,2    S1,3
//        [111:104] [79:72] [47:40] [15:8]      S2,0    S2,1    S2,2    S2,3
//        [103:96]  [71:64] [39:32] [7:0]       S3,0    S3,1    S3,2    S3,3
//
//   Equivalently, the values are packed into four words as given
//        [127:96]  [95:64] [63:32] [31:0]      w[0]    w[1]    w[2]    w[3]
/////////////////////////////////////////////

module aes_core(input  logic         clk, 
                input  logic         load,
                input  logic [127:0] key, 
                input  logic [127:0] plaintext, 
                output logic         done, 
                output logic [127:0] cyphertext);
// init vals ///////////////////////////////////
////////////////////////////////////////////////



// internal logic //////////////
	logic [0:3][0:3][7:0] aes_state;
	logic [127:0] cypher_intermediate;
	logic [127:0] round_key_done;
	logic [3:0] current_round;
	logic [127:0] current_round_key;
	
	//logic [127:0] shift_rows_done;
////////////////////////////////


// sub-module instantiation
	FSM();
	key_schedule();
	add_round_key ARK(plaintext, cypher_intermediate, current_round, current_round_key, round_key_done);
	sub_bytes SB(round_key_done, aes_state);
	//shift_rows SR(sub_bytes_done, shift_rows_done);
	//mix_cols MC(shift_rows_done, mix_cols_done);
    
endmodule

// key schedule ////////////////////////////////////////
// this generates the round key for all rounds based on the original key
////////////////////////////////////////////////////////
module key_schedule(
	input logic [127:0] key,
	output logic [127:0] current_round_key
	);
	
	//make words accessible
	assign word[0] = key[127:96]; //col4
	assign word[1] = key[95:64];  //col3
	assign word[2] = key[63:32];  //col2
	assign word[3] = key[31:0];   //col1
	
	
	
	
endmodule

module rot_word(
	input logic [31:0] key [3:0],
	output logic [127:0] rotated
	);
	
	rotated = key

endmodule

// sub bytes ///////////////////////////////
// this creates the S matrix (4x4 bytes) col major array
////////////////////////////////////////////
module sub_bytes(
	input logic [127:0] round_key_done,
	output logic [0:3][0:3][7:0] aes_state
	);
	
	// assigning all bytes in the data to the byte array
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

// add round key ////////////////////////////
// this uses an XOR with the current state of the data for each round given a different round key
////////////////////////////////////////////
module add_round_key (
	input logic [127:0] plaintext,
	input logic [127:0] cypher_intermediate,
	input logic [3:0] current_round,
	input logic [127:0] current_round_key,
	output logic [127:0] round_key_done);
	
	always_comb begin
		case(current_round)
			4'd1: round_key_done = plaintext ^ current_round_key;
			4'd2, 4'd3, 4'd4, 4'd5, 4'd6, 4'd7, 4'd8, 4'd9, 4'd10: round_key_done = cypher_intermediate ^ current_round_key;
			default: round_key_done = 128'd0;
		endcase
	end

endmodule

/////////////////////////////////////////////
// sbox
//   Infamous AES byte substitutions with magic numbers
//   Combinational version which is mapped to LUTs (logic cells)
//   Section 5.1.1, Figure 7
/////////////////////////////////////////////

//********************************** Sbox
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
	input logic [7:0] a,
	input logic clk,
	output logic [7:0] y);
            
  // sbox implemented as a ROM
  // This module is synchronous and will be inferred using BRAMs (Block RAMs)
  logic [7:0] sbox [0:255];

  initial   $readmemh("sbox.txt", sbox);
	
	// Synchronous version
	always_ff @(posedge clk) begin
		y <= sbox[a];
	end
endmodule
//**********************************

/////////////////////////////////////////////
// mixcolumns
//   Even funkier action on columns
//   Section 5.1.3, Figure 9
//   Same operation performed on each of four columns
/////////////////////////////////////////////

module mix_cols(input  logic [127:0] a,
                  output logic [127:0] y);

  mixcolumn mc0(a[127:96], y[127:96]);
  mixcolumn mc1(a[95:64],  y[95:64]);
  mixcolumn mc2(a[63:32],  y[63:32]);
  mixcolumn mc3(a[31:0],   y[31:0]);
endmodule

/////////////////////////////////////////////
// mixcolumn
//   Perform Galois field operations on bytes in a column
//   See EQ(4) from E. Ahmed et al, Lightweight Mix Columns Implementation for AES, AIC09
//   for this hardware implementation
/////////////////////////////////////////////

module mixcolumn(input  logic [31:0] a,
                 output logic [31:0] y);
                      
        logic [7:0] a0, a1, a2, a3, y0, y1, y2, y3, t0, t1, t2, t3, tmp;
        
        assign {a0, a1, a2, a3} = a;
        assign tmp = a0 ^ a1 ^ a2 ^ a3;
    
        galoismult gm0(a0^a1, t0);
        galoismult gm1(a1^a2, t1);
        galoismult gm2(a2^a3, t2);
        galoismult gm3(a3^a0, t3);
        
        assign y0 = a0 ^ tmp ^ t0;
        assign y1 = a1 ^ tmp ^ t1;
        assign y2 = a2 ^ tmp ^ t2;
        assign y3 = a3 ^ tmp ^ t3;
        assign y = {y0, y1, y2, y3};    
endmodule

/////////////////////////////////////////////
// galoismult
//   Multiply by x in GF(2^8) is a left shift
//   followed by an XOR if the result overflows
//   Uses irreducible polynomial x^8+x^4+x^3+x+1 = 00011011
/////////////////////////////////////////////

module galoismult(input  logic [7:0] a,
                  output logic [7:0] y);

    logic [7:0] ashift;
    
    assign ashift = {a[6:0], 1'b0};
    assign y = a[7] ? (ashift ^ 8'b00011011) : ashift;
endmodule