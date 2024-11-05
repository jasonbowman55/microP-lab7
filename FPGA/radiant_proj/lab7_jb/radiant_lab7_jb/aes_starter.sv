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
//   Tricky cases to properly change sdo on negedge clk//
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

// internal variables ////////////////////////////////////////////
    //key expansion
	logic [31:0] rot_word_done; 		//output modified word from rot_word in key expansion
    logic [31:0] sub_word_done; 	//output modified word from sub_bytes in key expansion
    logic [31:0] rcon_done;  			//output modified word from rcon module in key expansion
    logic [127:0] fill_round_key_done;  //output from fill_round_key in key expansion, full round key

    //main cypher
    logic [127:0] round_key_done;           //output from add round key in main cypher
    logic [127:0] sub_cyph_done;    	//output from sub bytes in main cypher
    logic [127:0] shift_rows_done;          //output from shift rows in main cypher 
    logic [127:0] mix_cols_done;            //output from the mix cols in main cypher

	// registers
	logic [127:0] round_key;		//current round key output from round key register
	logic [127:0] prev_round_key;			//previous round key output rot_word module
	logic [127:0] cypher_zero;				//output from the initial cypher register inside add_round_key
	logic [127:0] cyphertext_intermediate; 	//cypher text in between rounds

	// MUXs
	logic [127:0] cypher_src;				//output from the cypoher source mux
	logic [127:0] rk_src;					//output from the round key source mux
	logic [127:0] adrk_in;					//add round key block source
	
    //top level / controller_fsm module variables
	logic reset;							//dependant on load\\
	logic load_prev;						//used to generate reset
	logic [3:0] state;						//key schedule & cypher states
	logic done_int;							//done controll signal

//*************************TOP MODULE LOGIC*****************

	// done logic //////////////////////
	always_comb begin
		if (reset) begin
			cyphertext = 128'bx;
			done = 1'b0;
		end else if (done_int == 1) begin
			cyphertext = cyphertext_intermediate;
			done = 1'b1;
		end
	end
	///////////////////////////////////

	// reset logic //////////////////////
	always_ff @(posedge clk) begin
    		if (!load && load_prev) begin
        		reset <= 1;  
    		end else begin
        		reset <= 0;  
    		end
	end

	always_ff @(posedge clk) begin
		load_prev = load;
	end
	////////////////////////////////////

	
// **************SUB-MODULE INSTANTIATION*****************************
	//the main control, muxs, registers, and fsm module (CONTROLLER)
	controller CTR1(clk, reset, round_key_done, shift_rows_done, mix_cols_done, key, plaintext, fill_round_key_done, done_int, state, round_key, cyphertext_intermediate, adrk_in);

	//Key Schdule and expansion modules
    rot_word KS1(round_key, rot_word_done);
	sub_word KS2(clk, rot_word_done, sub_word_done);
	rcon KS3(state, round_key, sub_word_done, rcon_done);
	fill_round_key KS4(rcon_done, round_key, fill_round_key_done);
	
	//cypher stuff
	add_round_key CYPH1(adrk_in, round_key, round_key_done);
	sub_cyph CYPH2(clk, round_key_done, sub_cyph_done);
	shift_rows CYPH3(sub_cyph_done, shift_rows_done);
    mix_cols CYPH4(shift_rows_done, mix_cols_done);
//********************************************************************
endmodule

// FSM /////////////////////////////////////////////////
// This FSM block acts as the pacer and contoller of the system
// This is because all of these block rely on the state / round, thus need to be in this module
////////////////////////////////////////////////////////
module controller(
    input logic clk, reset,
    input logic [127:0] round_key_done, shift_rows_done, mix_cols_done, key, plaintext, fill_round_key_done,
    output logic done_int,
	output logic [3:0] state,
	output logic [127:0] round_key, cyphertext_intermediate, adrk_in
	);

	//state vasriables/////////
	//logic [3:0] state;		//current state of key schedule FSM
	logic [3:0] nextstate;	//next state for the key schedule portion of the BD
	logic [127:0] cypher_src, rk_src;
	///////////////////////////

    //instantiation of states for the FSM
    parameter S0 = 4'd0;
	parameter S1 = 4'd1;
    parameter S2 = 4'd2;
    parameter S3 = 4'd3;
    parameter S4 = 4'd4;
    parameter S5 = 4'd5;
    parameter S6 = 4'd6;
    parameter S7 = 4'd7;
    parameter S8 = 4'd8;
    parameter S9 = 4'd9;
    parameter S10 = 4'd10;
    parameter S11 = 4'd11;
	parameter S12 = 4'd12;
    logic [3:0] timer = 4'd0;
logic [3:0] timer_limit = 5;

/////////////////////////////////////////

// Next state logic and timer update //
always_ff @(posedge clk) begin
	if (reset) begin
		state <= S0;
		timer <= 4'd0;
	end else begin
		state <= nextstate;
		if (state == nextstate && timer < timer_limit) // Only increment timer within the same state
			timer <= timer + 1;
		else
			timer <= 4'd0; // Reset timer when moving to a new state
	end
end

/////////////////////////////////////////

// Main FSM //
always_comb begin
	nextstate = state; // Default to remain in the current state
	case (state)
		S0: begin
			if (reset)
				nextstate = S0;
			else
				nextstate = S1;
		end
		S1: begin
			if (timer >= timer_limit)
				nextstate = S2;
		end
		S2: begin
			if (timer >= timer_limit)
				nextstate = S3;
		end
		S3: begin
			if (timer >= timer_limit)
				nextstate = S4;
		end
		S4: begin
			if (timer >= timer_limit)
				nextstate = S5;
		end
		S5: begin
			if (timer >= timer_limit)
				nextstate = S6;
		end
		S6: begin
			if (timer >= timer_limit)
				nextstate = S7;
		end
		S7: begin
			if (timer >= timer_limit)
				nextstate = S8;
		end
		S8: begin
			if (timer >= timer_limit)
				nextstate = S9;
		end
		S9: begin
			if (timer >= timer_limit)
				nextstate = S10;
		end
		S10: begin
			if (timer >= timer_limit)
				nextstate = S11;
		end
		S11: begin
			if (timer >= timer_limit)
				nextstate = S12;
		end
		S12: begin
			if (timer >= timer_limit)
				nextstate = S12; // Remain in S12
		end
	endcase
end

	////////////////////////////////////////

	// MUXs ********************************************************
	// source mux for the cyphertext line //////////////////////////
	always_comb begin
		if (reset) begin
        		cypher_src <= 128'b0;
		end else begin
			case(state)
				S1:
					cypher_src <= plaintext;
				S2, S3, S4, S5, S6, S7, S8, S9, S10, S11, S12:
					cypher_src <= round_key_done;
				default:
					cypher_src <= 128'bx;
			endcase
		end
	end
	////////////////////////////////////////////////////////////////
	
	// mux src for the cound key source ////////////////////////////
	always_comb begin
		if (reset) begin
        	rk_src <= 128'b0;
		end else begin
				case(state)
					S1: rk_src <= key;
					S2, S3, S4, S5, S6, S7, S8, S9, S10, S11, S12:
						  rk_src <= fill_round_key_done;
					default:
						  rk_src <= 128'bx;
				endcase
		end
	end
	////////////////////////////////////////////////////////////////

	logic [127:0] adrk_src;
	always_comb begin
		if (reset) begin
        	adrk_src <= 128'b0;
		end else begin
				case(state)
					S1: adrk_src <= cyphertext_intermediate;
					S2, S3, S4, S5, S6, S7, S8, S9, S10:
						adrk_src <= mix_cols_done;
					S11, S12:
						adrk_src <= shift_rows_done;
					default:
						  adrk_src <= 128'bx;
				endcase
		end
	end
	// mux src for add round key block input //////////////////////
	
	///////////////////////////////////////////////////////////////
	//**************************************************************
	

	// register to hold the value of fill round key done for two extra clk cycles
	logic [127:0] adrk_src_temp;
	logic [127:0] adrk_src_delay;

	always_ff @(posedge clk) begin
    		if (reset) begin
        		adrk_src_delay <= 128'bx;
        		adrk_src_temp <= 128'bx;
    		end else begin
        		adrk_src_delay <= adrk_src;     // First cycle delay
        		adrk_src_temp <= adrk_src_delay;     // Second cycle delay
    		end
	end

	always_ff @(posedge clk) begin
		if (reset)
			adrk_in <= 128'b0;
		else if (timer == 3)
			adrk_in <= adrk_src_temp;
	end
	////////////////////////////////////////////////////////////////////////////

	// flip flip enable logic **************************************
		// register to hold cyphertext //////////////
	always_ff @(posedge clk) begin
		if (reset)
			cyphertext_intermediate <= 128'b0;
		else if (timer == 0)
			cyphertext_intermediate <= cypher_src;
	end
	/////////////////////////////////////////////
	
	// register to hold the value of fill round key done for two extra clk cycles
	logic [127:0] fill_round_key_temp;
	logic [127:0] fill_round_key_delay;

	always_ff @(posedge clk) begin
    		if (reset) begin
        		fill_round_key_delay <= 128'bx;
        		fill_round_key_temp <= 128'bx;
    		end else begin
        		fill_round_key_delay <= fill_round_key_done;     // First cycle delay
        		fill_round_key_temp <= fill_round_key_delay;     // Second cycle delay
    		end
	end
	////////////////////////////////////////////////////////////////////////////

	// current round key register /////////////////
	always_ff @(posedge clk) begin
		if (reset)
			round_key = 128'bx;
		else begin
 			case(state)
				S1:
					round_key = key;
				S2, S3, S4, S5, S6, S7, S8, S9, S10, S11:
					if(timer == 0)
					round_key = fill_round_key_temp;
				default:
					round_key = 128'bx;
			endcase
		end
	end
	//////////////////////////////////////////////
	//***************************************************************
	
	// done logic //////////////////////
logic done_int_delay = 0;
logic break_loop = 0;

always_ff @(posedge clk or posedge reset) begin
	if (reset) begin
		done_int_delay <= 1'b0;
		done_int <= 1'b0;
	end else if (state == S12 && break_loop == 0) begin
		done_int_delay <= 1'b1;
		done_int <= done_int_delay;
		break_loop = break_loop + 1;
	end else begin
		done_int_delay <= 1'b0;
		done_int <= done_int_delay;
	end
end

	///////////////////////////////////
endmodule

// rot_word /////////////////////////////
// this is the first step to the key schedule process
/////////////////////////////////////////
module rot_word(
	input logic [127:0] round_key,
	output logic [31:0] rot_word_done
	);
	
	// internal variables /////
	logic [31:0] w3;	//most right col in round key
	logic [7:0] B1;		//first byte from top in the col
	logic [7:0] B2;		//second byte from top in the col
	logic [7:0] B3;		//third byte from top in the col
	logic [7:0] B4;		//fourth byte from top in the col
	//////////////////////////
	
	// init vals /////////////
	always_comb begin
		w3 = round_key[31:0]; //last word in round key
		B1 = w3[31:24];
		B2 = w3[23:16];
		B3 = w3[15:8];
		B4 = w3[7:0];
	
		// set output ///////////////////////////////////////////
		rot_word_done = {B2, B3, B4, B1};
	end
	/////////////////////////////////////////////////////////
endmodule

// sub bytes ///////////////////////////////
// this creates the S matrix (4x4 bytes) col major array
////////////////////////////////////////////
module sub_word( //DO I NEED CLK AND RESET?
	input logic clk,
	input logic [31:0] rot_word_done,
	output logic [31:0] sub_word_done
	);
	// perform sub bytes word by word using sbox_sync ////////////
	sbox_sync s0(rot_word_done[31:24], clk, sub_word_done[31:24]);
	sbox_sync s1(rot_word_done[23:16], clk, sub_word_done[23:16]);
	sbox_sync s2(rot_word_done[15:8], clk, sub_word_done[15:8]);
	sbox_sync s3(rot_word_done[7:0], clk, sub_word_done[7:0]);
	//////////////////////////////////////////////////////////////
endmodule

// Rcon ///////////////////////////////////////////////
// this is the second step in the key schedule expander
///////////////////////////////////////////////////////
module rcon (
	input logic [3:0] state,
	input logic [127:0] round_key,
	input logic [31:0] sub_word_done,
	output logic [31:0] rcon_done
	);
	
	// internal variables //
	logic [31:0] rcon[0:9] = '{	 32'h01000000,
								 32'h02000000,
								 32'h04000000,
								 32'h08000000,
								 32'h10000000,
								 32'h20000000,
								 32'h40000000,
								 32'h80000000,
								 32'h1B000000,
								 32'h36000000 };	//Rcon matrix
	////////////////////////
	
	// variable assignment logic ////////
	logic [31:0] rcon_done_intermediate;

	always_comb begin
        if (state != 0) begin								   //ensure in correct round bounds
            //rcon_done = prev_round_key[127:96] ^ sub_bytes_done ^ rcon[round]; //XOR operation with the first word of previous RK, calculated sub_bytes word, and rcon value based on round
		rcon_done_intermediate = round_key [127:96] ^ sub_word_done;
		rcon_done = rcon_done_intermediate ^ rcon[state - 1];
        end else begin
            rcon_done = 32'bx;
        end
    end
	//////////////////////////////////////
endmodule

// fill_round_key //////////////////////////////////////////
// this works to complete the last 3 XOR statements to fill col[1, 2, 3] in the new round key
////////////////////////////////////////////////////////////
module fill_round_key(
	input logic [31:0] rcon_done,
	input logic [127:0] round_key,
	output logic [127:0] fill_round_key_done
	);
	// fill the full round key with the following XOR statements
	// use blocking statements so that following calculations can be done with the previously calculated values
	always_comb begin
		fill_round_key_done[127:96] = rcon_done;
		fill_round_key_done[95:64] = round_key[95:64] ^ fill_round_key_done[127:96];
		fill_round_key_done[63:32] = round_key[63:32] ^ fill_round_key_done[95:64];
		fill_round_key_done[31:0] = round_key[31:0] ^ fill_round_key_done[63:32];	
	end
	////////////////////////////////////////////////////////////////////////////////////////////////////////////
endmodule

//******************************************************
// NEW CODE BELOW THIS PERTAINS TO ALTERING CYPHERTEXT
//******************************************************

// add round key ////////////////////////////
// this uses an XOR with the current state of the data for each round given a different round key
////////////////////////////////////////////
module add_round_key (
	input logic [127:0] adrk_in,
	input logic [127:0] round_key,
	output logic [127:0] round_key_done
	);
	// add round key logic XOR cyphertext with current round key
	always_comb begin
		round_key_done <= adrk_in ^ round_key;
	end
	////////////////////////////////////////////////////////////
endmodule

// sub bytes for the cypher /////////////////////////
// this is the second thing to do in the cypher side of the AES-128
/////////////////////////////////////////////////////
module sub_cyph( //DO I NEED CLK AND RESET?
	input logic clk,
	input logic [127:0] round_key_done,
	output logic [127:0] sub_cyph_done
	);
	// perform sub bytes on full intermediate cypher with sbox_sync
	sbox_sync s4(round_key_done[7:0], clk, sub_cyph_done[7:0]);
	sbox_sync s5(round_key_done[15:8], clk, sub_cyph_done[15:8]);
	sbox_sync s6(round_key_done[23:16], clk, sub_cyph_done[23:16]);
	sbox_sync s7(round_key_done[31:24], clk, sub_cyph_done[31:24]);
	sbox_sync s8(round_key_done[39:32], clk, sub_cyph_done[39:32]);
	sbox_sync s9(round_key_done[47:40], clk, sub_cyph_done[47:40]);
	sbox_sync s10(round_key_done[55:48], clk, sub_cyph_done[55:48]);
	sbox_sync s11(round_key_done[63:56], clk, sub_cyph_done[63:56]);
	sbox_sync s12(round_key_done[71:64], clk, sub_cyph_done[71:64]);
	sbox_sync s13(round_key_done[79:72], clk, sub_cyph_done[79:72]);
	sbox_sync s14(round_key_done[87:80], clk, sub_cyph_done[87:80]);
	sbox_sync s15(round_key_done[95:88], clk, sub_cyph_done[95:88]);
	sbox_sync s16(round_key_done[103:96], clk, sub_cyph_done[103:96]);
	sbox_sync s17(round_key_done[111:104], clk, sub_cyph_done[111:104]);
	sbox_sync s18(round_key_done[119:112], clk, sub_cyph_done[119:112]);
	sbox_sync s19(round_key_done[127:120], clk, sub_cyph_done[127:120]);
	////////////////////////////////////////////////////////////
endmodule
//////////////////////////////////////////////////////

// shift rows/////////////////////////////////////////
// this works on shifiting the rows in the cypher section of the algorithm
//////////////////////////////////////////////////////
module shift_rows(
	input logic [127:0] sub_cyph_done,
	output logic [127:0] shift_rows_done
	);
	
	//internal variables
	logic [7:0] cypher_matrix[3:0][3:0];
	////////////////////
	
	// create cypher matrix to more easily shift rows /////////
	assign cypher_matrix[0][0] = sub_cyph_done[127:120];
	assign cypher_matrix[1][0] = sub_cyph_done[119:112];
	assign cypher_matrix[2][0] = sub_cyph_done[111:104];
	assign cypher_matrix[3][0] = sub_cyph_done[103:96];

	assign cypher_matrix[0][1] = sub_cyph_done[95:88];
	assign cypher_matrix[1][1] = sub_cyph_done[87:80];
	assign cypher_matrix[2][1] = sub_cyph_done[79:72];
	assign cypher_matrix[3][1] = sub_cyph_done[71:64];

	assign cypher_matrix[0][2] = sub_cyph_done[63:56];
	assign cypher_matrix[1][2] = sub_cyph_done[55:48];
	assign cypher_matrix[2][2] = sub_cyph_done[47:40];
	assign cypher_matrix[3][2] = sub_cyph_done[39:32];

	assign cypher_matrix[0][3] = sub_cyph_done[31:24];
	assign cypher_matrix[1][3] = sub_cyph_done[23:16];
	assign cypher_matrix[2][3] = sub_cyph_done[15:8];
	assign cypher_matrix[3][3] = sub_cyph_done[7:0];
	///////////////////////////////////////////////////////////
	
	// perform shift row logic ////////////////////////////////
	always_comb begin
		// row 0: no shift
        shift_rows_done[127:120] = cypher_matrix[0][0];
        shift_rows_done[119:112] = cypher_matrix[1][1];
        shift_rows_done[111:104] = cypher_matrix[2][2];
        shift_rows_done[103:96]  = cypher_matrix[3][3];

        // row 1: shift left by 1
        shift_rows_done[95:88]   = cypher_matrix[0][1];
        shift_rows_done[87:80]   = cypher_matrix[1][2];
        shift_rows_done[79:72]   = cypher_matrix[2][3];
        shift_rows_done[71:64]   = cypher_matrix[3][0];

        // row 2: shift left by 2
        shift_rows_done[63:56]   = cypher_matrix[0][2];
        shift_rows_done[55:48]   = cypher_matrix[1][3];
        shift_rows_done[47:40]   = cypher_matrix[2][0];
        shift_rows_done[39:32]   = cypher_matrix[3][1];

        // row 3: shift left by 3
        shift_rows_done[31:24]   = cypher_matrix[0][3];
        shift_rows_done[23:16]   = cypher_matrix[1][0];
        shift_rows_done[15:8]    = cypher_matrix[2][1];
        shift_rows_done[7:0]     = cypher_matrix[3][2];
    end
	///////////////////////////////////////////////////////////
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