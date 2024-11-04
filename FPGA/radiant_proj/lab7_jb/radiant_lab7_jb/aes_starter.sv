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
    logic [31:0] sub_bytes_KS_done; 	//output modified word from sub_bytes in key expansion
    logic [31:0] rcon_done;  			//output modified word from rcon module in key expansion
    logic [127:0] fill_round_key_done;  //output from fill_round_key in key expansion, full round key

    //main cypher
    logic [127:0] round_key_done;           //output from add round key in main cypher
    logic [127:0] sub_bytes_done_CYPH;    	//output from sub bytes in main cypher
    logic [127:0] shift_rows_done;          //output from shift rows in main cypher 
    logic [127:0] mix_cols_done;            //output from the mix cols in main cypher

	// registers
	logic [127:0] current_round_key;		//current round key output from round key register
	logic [127:0] prev_round_key;			//previous round key output rot_word module
	logic [127:0] cypher_zero;				//output from the initial cypher register inside add_round_key
	logic [127:0] cyphertext_intermediate; 	//cypher text in between rounds

	// MUXs
	logic [127:0] cypher_src;				//output from the cypoher source mux
	logic [127:0] rk_src;					//output from the round key source mux
	
    //top level / controller_fsm module variables
    logic [3:0] round;       				//stores the round number 0-10 (each round = 2 clk cycles
	logic reset;							//dependant on load\\
	logic load_prev;						//used to generate reset
	logic [2:0] state_KS, state_CYPH;				//key schedule & cypher states
	logic done_int;							//internal done signal to say that the cyphertext is complete

//*************************TOP MODULE LOGIC*****************

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
	
	// done logic //////////////////////
	always_comb begin
		if (reset) begin
			done = 1'b0;
			cyphertext = 128'bx;
		end else if (done_int) begin
			done = 1'b1;
			cyphertext = cyphertext_intermediate;
		end
	end
	///////////////////////////////////
	
// **************SUB-MODULE INSTANTIATION*****************************
	//the main control, muxs, registers, and fsm module (CONTROLLER)
	fsm CTR1(clk, reset, done_int, round, state_KS, state_CYPH);
	hold CTR2(clk, reset, round, round_key_done, state_KS, state_CYPH, cypher_src, rk_src, cypher_zero, cyphertext_intermediate, current_round_key, prev_round_key);
	source CTR3(reset, round, state_KS, state_CYPH, cypher_zero, plaintext, shift_rows_done, mix_cols_done, key, fill_round_key_done, round_key_done, cypher_src, rk_src);

	//Key Schdule and expansion modules
    rot_word KS1(current_round_key, rot_word_done);
	sub_bytes_KS KS2(clk, rot_word_done, sub_bytes_KS_done);
	rcon KS3(round, state_KS, prev_round_key, sub_bytes_KS_done, rcon_done);
	fill_round_key KS4(rcon_done, prev_round_key, fill_round_key_done);
	
	//cypher stuff
	add_round_key CYPH1(cyphertext_intermediate, current_round_key, round_key_done);
	sub_bytes_CYPH CYPH2(clk, round_key_done, sub_bytes_done_CYPH);
	shift_rows CYPH3(sub_bytes_done_CYPH, shift_rows_done);
    mix_cols CYPH4(shift_rows_done, mix_cols_done);
//********************************************************************
endmodule

// FSM /////////////////////////////////////////////////
// This FSM block acts as the pacer and contoller of the system
// This is because all of these block rely on the state / round, thus need to be in this module
////////////////////////////////////////////////////////
module fsm(
    input logic clk, reset,
    output logic done_int,
	output logic [3:0] round,
	output logic [2:0] state_KS, state_CYPH
	);

	//state vasriables/////////
	//logic [1:0] state_KS;		//current state of key schedule FSM
	logic [2:0] nextstate_KS;	//next state for the key schedule portion of the BD
	//logic [1:0] state_CYPH;		//current state of cypher FSM
	logic [2:0] nextstate_CYPH;	//next state for the cypher portion of the BD
	///////////////////////////

    //instantiation of states for the FSM
    parameter S0_KS = 3'b000; 		//initial state
	parameter S0_CYPH = 3'b000;
	parameter KS1 = 3'b001; 	//rot_word -> STARTsub_bytes
	parameter KS2 = 3'b010; 	//ENDsub_bytes -> Rcon -> fill_round_key
	parameter KS3 = 3'b011;
	parameter KS4 = 3'b100;
	parameter KS5 = 3'b101;
	parameter CYPH1 = 3'b001; 	//ass_round_key -> STARTsub_bytes
	parameter CYPH2 = 3'b010; 	//ENDsub_bytes -> shift_rows -> mix_cols
	parameter CYPH3 = 3'b011;
	parameter CYPH4 = 3'b100;
	parameter CYPH5 = 3'b101;

    /////////////////////////////////////

    //next state logic (key schedule)/////////
    always_ff @(posedge clk)
		if (reset) 
			state_KS <= S0_KS;
		else 	
			state_KS <= nextstate_KS;
	//////////////////////////////////////////

    //next state logic (cypher)///////////////
     always_ff @(posedge clk)
		if (reset) 
			state_CYPH <= S0_CYPH;
		else 	
			state_CYPH <= nextstate_CYPH;
    //////////////////////////////////////////

    //FSM machines for (key schedule)///////////
    always_comb begin
        case(state_KS)
			S0_KS:
				if (reset)					//wait for plain text to load before starting fsm loop
					nextstate_KS = S0_KS;
				else
					nextstate_KS = KS1;
            KS1:
                nextstate_KS = KS2;
            KS2:
                nextstate_KS = KS3;
	    KS3:
                nextstate_KS = KS4;
		KS4:
				nextstate_KS = KS5;
		KS5: 
			nextstate_KS = KS1;
			default:
				nextstate_KS = S0_KS;
        endcase
    end
	////////////////////////////////////////////
	
    //FSM machines for (key cypher)/////////////
    always_comb begin
        case(state_CYPH)
			S0_CYPH:
				if (reset)					//wait for plain text to load before starting fsm loop
					nextstate_CYPH = S0_CYPH;
				else
					nextstate_CYPH = CYPH1;
			CYPH1:
                		nextstate_CYPH = CYPH2;
            		CYPH2:
                		nextstate_CYPH = CYPH3;
			CYPH3:
                		nextstate_CYPH = CYPH4;
			CYPH4:
						nextstate_CYPH = CYPH5;
			CYPH5: 
				nextstate_CYPH = CYPH1;
			default:
				nextstate_CYPH = S0_CYPH;
        endcase
    end
	////////////////////////////////////////////

	// round counter ///////////////////////////
	always_ff @(posedge clk) begin
		if (reset) begin
			round <= 4'd0;
		end else if (state_KS == KS5) begin
			if (round < 10) 
				round <= round + 1;
		end
	end
	////////////////////////////////////////////

	// done_int flag
	always_ff @(posedge clk) begin
		if (reset) begin
			done_int <= 1'b0;
		end else if (round == 10) begin
			done_int = 1'b1;
		end
	end

endmodule

// holding ////////////////////////////////////////
// this module holds all oif the registers that hold intermitant values
///////////////////////////////////////////////////
module hold (
	input logic clk, reset,
	input logic [3:0] round,
	input logic [127:0] round_key_done,
	input logic [2:0] state_KS, state_CYPH,
	input logic [127:0] cypher_src, rk_src,
	output logic [127:0] cypher_zero, cyphertext_intermediate, current_round_key, prev_round_key
	);

	// register to hold cyphertext
	always_ff @(posedge clk) begin
		if (reset)
			cyphertext_intermediate = 128'b0;
		else
			cyphertext_intermediate = cypher_src;
	end
	
	// register to hold the first cypher text
	always_ff @(posedge clk) begin
		if (reset)
			cypher_zero = 128'b0;
		else if (round == 0 && state_CYPH == 3'b010)  //2'b10 = CYPH2
			cypher_zero = round_key_done;
	end
	////////////////////////////////
	
	

	// current round key register
	always_ff @(posedge clk) begin
		if (reset)
			current_round_key = 128'bx;
		else begin
			case(round)
				4'd0: begin
					if (state_KS == 3'b000)
						current_round_key = rk_src;
				      end
				default: begin
					if (state_KS == 3'b101)
						current_round_key = rk_src;
					 end
			endcase
		end
	end
	
	
	// previous round key register
	always_ff @(posedge clk) begin
		if (reset)
			prev_round_key = 128'bx;
		else
			prev_round_key = current_round_key;
	end
	////////////////////////////////////////////////////////////////////
endmodule

// source //////////////////////////////////////
// this module operates the MUXs used to input into the registers given a ceratin round
////////////////////////////////////////////////
module source(
	input logic reset,
	input logic [3:0] round,
	input logic [2:0] state_KS, state_CYPH,
	input logic [127:0] cypher_zero, plaintext, shift_rows_done, mix_cols_done, key, fill_round_key_done, round_key_done,
	output logic [127:0] cypher_src, rk_src
	);

	// source mux for the cyphertext line //////////////////////////
	always_comb begin
		if (reset) begin
        		cypher_src <= 128'b0;
		end else begin
			case(round)
				4'd0:
					cypher_src = plaintext;
				4'd1:
					cypher_src = cypher_zero;
				4'd2, 4'd3, 4'd4, 4'd5, 4'd6, 4'd7, 4'd8, 4'd9: 
					cypher_src = mix_cols_done;
				4'd10:
					cypher_src = shift_rows_done;
				default:
					cypher_src = 128'bx;
			endcase
		end
	end
	////////////////////////////////////////////////////////////////
//
	// mux src for the cound key source ////////////////////////////
	always_comb begin
		if (reset) begin
        	rk_src <= 128'b0;
		end else begin
				case(round)
					4'd0: rk_src = key;
					4'd1, 4'd2, 4'd3, 4'd4, 4'd5, 4'd6, 4'd7, 4'd8, 4'd9, 4'd10:
						  rk_src = fill_round_key_done;
					default:
						  rk_src = 128'bx;
				endcase
		end
	end
	////////////////////////////////////////////////////////////////
endmodule

// rot_word /////////////////////////////
// this is the first step to the key schedule process
/////////////////////////////////////////
module rot_word(
	input logic [127:0] current_round_key,
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
		w3 = current_round_key[31:0]; //last word in round key
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
module sub_bytes_KS( //DO I NEED CLK AND RESET?
	input logic clk,
	input logic [31:0] rot_word_done,
	output logic [31:0] sub_bytes_KS_done
	);
	// perform sub bytes word by word using sbox_sync ////////////
	sbox_sync s0(rot_word_done[31:24], clk, sub_bytes_KS_done[31:24]);
	sbox_sync s1(rot_word_done[23:16], clk, sub_bytes_KS_done[23:16]);
	sbox_sync s2(rot_word_done[15:8], clk, sub_bytes_KS_done[15:8]);
	sbox_sync s3(rot_word_done[7:0], clk, sub_bytes_KS_done[7:0]);
	//////////////////////////////////////////////////////////////
endmodule

// Rcon ///////////////////////////////////////////////
// this is the second step in the key schedule expander
///////////////////////////////////////////////////////
module rcon (
	input logic [3:0] round,
	input logic [2:0] state_KS,
	input logic [127:0] prev_round_key,
	input logic [31:0] sub_bytes_KS_done,
	output logic [31:0] rcon_done
	);
	
	// internal variables //
	logic [31:0] rcon[0:9] = '{				 32'h01000000,
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
	
	// variable assignment logic ////.////
	always_comb begin
        if (round >= 0) begin								   //ensure in correct round bounds
            //rcon_done = prev_round_key[127:96] ^ sub_bytes_done ^ rcon[round]; //XOR operation with the first word of previous RK, calculated sub_bytes word, and rcon value based on round
		rcon_done = sub_bytes_KS_done ^ rcon[round];
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
	input logic [127:0] prev_round_key,
	output logic [127:0] fill_round_key_done
	);
	// fill the full round key with the following XOR statements
	// use blocking statements so that following calculations can be done with the previously calculated values
	always_comb begin
		fill_round_key_done[127:96] = rcon_done;
		fill_round_key_done[95:64] = prev_round_key[95:64] ^ fill_round_key_done[127:96];
		fill_round_key_done[63:32] = prev_round_key[63:32] ^ fill_round_key_done[95:64];
		fill_round_key_done[31:0] = prev_round_key[31:0] ^ fill_round_key_done[63:32];	
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
	input logic [127:0] cyphertext_intermediate,
	input logic [127:0] current_round_key,
	output logic [127:0] round_key_done
	);
	// add round key logic XOR cyphertext with current round key
	always_comb begin
		round_key_done <= cyphertext_intermediate ^ current_round_key;
	end
	////////////////////////////////////////////////////////////
endmodule

// sub bytes for the cypher /////////////////////////
// this is the second thing to do in the cypher side of the AES-128
/////////////////////////////////////////////////////
module sub_bytes_CYPH( //DO I NEED CLK AND RESET?
	input logic clk,
	input logic [127:0] round_key_done,
	output logic [127:0] sub_bytes_done_CYPH
	);
	// perform sub bytes on full intermediate cypher with sbox_sync
	sbox_sync s4(round_key_done[7:0], clk, sub_bytes_done_CYPH[7:0]);
	sbox_sync s5(round_key_done[15:8], clk, sub_bytes_done_CYPH[15:8]);
	sbox_sync s6(round_key_done[23:16], clk, sub_bytes_done_CYPH[23:16]);
	sbox_sync s7(round_key_done[31:24], clk, sub_bytes_done_CYPH[31:24]);
	sbox_sync s8(round_key_done[39:32], clk, sub_bytes_done_CYPH[39:32]);
	sbox_sync s9(round_key_done[47:40], clk, sub_bytes_done_CYPH[47:40]);
	sbox_sync s10(round_key_done[55:48], clk, sub_bytes_done_CYPH[55:48]);
	sbox_sync s11(round_key_done[63:56], clk, sub_bytes_done_CYPH[63:56]);
	sbox_sync s12(round_key_done[71:64], clk, sub_bytes_done_CYPH[71:64]);
	sbox_sync s13(round_key_done[79:72], clk, sub_bytes_done_CYPH[79:72]);
	sbox_sync s14(round_key_done[87:80], clk, sub_bytes_done_CYPH[87:80]);
	sbox_sync s15(round_key_done[95:88], clk, sub_bytes_done_CYPH[95:88]);
	sbox_sync s16(round_key_done[103:96], clk, sub_bytes_done_CYPH[103:96]);
	sbox_sync s17(round_key_done[111:104], clk, sub_bytes_done_CYPH[111:104]);
	sbox_sync s18(round_key_done[119:112], clk, sub_bytes_done_CYPH[119:112]);
	sbox_sync s19(round_key_done[127:120], clk, sub_bytes_done_CYPH[127:120]);
	////////////////////////////////////////////////////////////
endmodule
//////////////////////////////////////////////////////

// shift rows/////////////////////////////////////////
// this works on shifiting the rows in the cypher section of the algorithm
//////////////////////////////////////////////////////
module shift_rows(
	input logic [127:0] sub_bytes_done_CYPH,
	output logic [127:0] shift_rows_done
	);
	
	//internal variables
	logic [7:0] cypher_matrix[3:0][3:0];
	////////////////////
	
	// create cypher matrix to more easily shift rows /////////
	assign cypher_matrix[0][0] = sub_bytes_done_CYPH[127:120];
	assign cypher_matrix[1][0] = sub_bytes_done_CYPH[119:112];
	assign cypher_matrix[2][0] = sub_bytes_done_CYPH[111:104];
	assign cypher_matrix[3][0] = sub_bytes_done_CYPH[103:96];

	assign cypher_matrix[0][1] = sub_bytes_done_CYPH[95:88];
	assign cypher_matrix[1][1] = sub_bytes_done_CYPH[87:80];
	assign cypher_matrix[2][1] = sub_bytes_done_CYPH[79:72];
	assign cypher_matrix[3][1] = sub_bytes_done_CYPH[71:64];

	assign cypher_matrix[0][2] = sub_bytes_done_CYPH[63:56];
	assign cypher_matrix[1][2] = sub_bytes_done_CYPH[55:48];
	assign cypher_matrix[2][2] = sub_bytes_done_CYPH[47:40];
	assign cypher_matrix[3][2] = sub_bytes_done_CYPH[39:32];

	assign cypher_matrix[0][3] = sub_bytes_done_CYPH[31:24];
	assign cypher_matrix[1][3] = sub_bytes_done_CYPH[23:16];
	assign cypher_matrix[2][3] = sub_bytes_done_CYPH[15:8];
	assign cypher_matrix[3][3] = sub_bytes_done_CYPH[7:0];
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