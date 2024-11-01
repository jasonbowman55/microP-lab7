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

// internal variables ////////////////////////////////////////////
    //key expansion
	logic [31:0] rot_word_done; 		//output modified word from rot_word in key expansion
    logic [31:0] sub_bytes_KS_done; 	//output modified word from sub_bytes in key expansion
    logic [31:0] rcon_done;  			//output modified word from rcon module in key expansion
    logic [127:0] fill_round_key_done;  //output from fill_round_key in key expansion, full round key

    //main cypher
    logic [127:0] round_key_done;           //output from add round key in main cypher
    logic [127:0] sub_bytes_cypher_done;    //output from sub bytes in main cypher
    logic [127:0] shift_rows_done;          //output from shift rows in main cypher 
    logic [127:0] mix_cols_done;            //output from the mix cols in main cypher
    logic [127:0] cyphertext_intermediate;  //output from cypher register
	logic [127:0] final_cypher_text;		//ouput from register inside shift rows

    //Register enables and output logic
    logic [1:0] rk_en;
    logic init_cyph_en, prev_rk_en, final_cyph_en;  //rk_en: chooses key origin / init_cyph_one_en: enable register to hold cypher after round 0 calc in add_round_key / prev_rk_en: store prev RK in rot_word
    logic [2:0] cyph_en; 					//enables current cyphertext and alters input based on state
	logic [127:0] current_round_key;		//current round key output from round key register
	logic [127:0] prev_round_key;			//previous round key output rot_word module
	logic [127:0] cypher_zero;			//output from the initial cypher register inside add_round_key

    //state and round variables
    logic [3:0] round;       //stores the round number 0-10 (each round = 2 clk cycles
    logic [3:0] state_KS;    //current state of the Key Schedule FSM
	logic [3:0] state_CYPH;  //current state of the Cypher the
//////////////////////////////////////////////////////////////////

// top level register logic ***************************
	// round key regsiter //////////////////////////
	always_ff @(posedge clk) begin
		if (rk_en == 2'b00)
			current_round_key = key;
		else if (rk_en == 2'b01)
			current_round_key = fill_round_key_done;
		else if (rk_en == 2'b10)
			current_round_key = current_round_key;
	end
	//always_comb begin
	//	case(rk_en)
	//		1'b0: current_round_key = key;
	//		1'b1: current_round_key = fill_round_key_done;
	//	endcase
	//end
	////////////////////////////////////////////////
	
	// cypher register////////////////////////////////
	//always_ff @(posedge clk) begin
		//if (cyph_en == 2'b00)
			//cyphertext_intermediate = plaintext;
		//else if (cyph_en == 2'b01)
			//cyphertext_intermediate = mix_cols_done;
		//else if (cyph_en == 2'b10)
			//cyphertext_intermediate = shift_rows_done;
		//else if (cyph_en == 2'b11)
			//cyphertext_intermediate = cypher_zero;
	//end
	always_comb begin
		case(cyph_en)
			3'b000: cyphertext_intermediate = plaintext;
			3'b001: cyphertext_intermediate = mix_cols_done;
			3'b010: cyphertext_intermediate = final_cypher_text;
			3'b011: cyphertext_intermediate = cypher_zero;
			3'b100: cyphertext_intermediate = cyphertext_intermediate;
			default: cyphertext_intermediate = 128'dx;
		endcase
	end
	//////////////////////////////////////////////////
//*****************************************************
	
//*****************************************************
// reset logic based on the val of load
	// load based reset ////////////////////////
	logic reset; // Declare reset as a register
	logic load_prev;
	
	// reset when load and load_prev are in this state for one clk cycle
	always_ff @(posedge clk) begin
    		if (!load && load_prev) begin
        		reset <= 1;  
    		end else begin
        		reset <= 0;  
    		end
	end
	////////////////////////////////////////////////////////////////////

	// load_prev gets load/////////
	always_ff @(posedge clk) begin
		load_prev = load;
	end
	///////////////////////////////
	
// sub-module instantiation /////////////////
	//FSM
	fsm FSM1(clk, reset, round, rk_en, init_cyph_en, prev_rk_en, final_cyph_en, cyph_en);
	
	//Key Schdule and expansion modules
    rot_word KS1(clk, reset, current_round_key, prev_rk_en, prev_round_key, rot_word_done);
	sub_bytes_KS KS2(clk, rot_word_done, sub_bytes_KS_done);
	rcon KS3(prev_round_key, sub_bytes_KS_done, round, rcon_done);
	fill_round_key KS4(rcon_done, prev_round_key, fill_round_key_done);
	
	//cypher stuff
	add_round_key CYPH1(clk, cyphertext_intermediate, current_round_key, init_cyph_en, cypher_zero, round_key_done);
	sub_bytes_CYPH CYPH2(clk, round_key_done, sub_bytes_cypher_done);
	shift_rows CYPH3(clk, final_cyph_en, sub_bytes_cypher_done, shift_rows_done, final_cypher_text);
    mix_cols CYPH4(shift_rows_done, mix_cols_done);
/////////////////////////////////////////////
endmodule

// FSM /////////////////////////////////////////////////
// This FSM block includes many things. The main FSM for both the Key Schedule and Cypher half of the bock diagram, and the following
// - round counter / register enable logic / cypher & round key FSM / 
// This is because all of these block rely on the state, thus need to be in this module
////////////////////////////////////////////////////////
module fsm(
    input logic clk, reset,
    output logic [3:0] round,
	output logic [1:0] rk_en,
	output logic init_cyph_en, prev_rk_en, final_cyph_en,
	output logic [2:0] cyph_en
);

	//internal vasriables//////
	logic [3:0] state_KS;		//current state of key schedule FSM
	logic [3:0] nextstate_KS;	//next state for the key schedule portion of the BD
	logic [3:0] state_CYPH;		//current state of cypher FSM
	logic [3:0] nextstate_CYPH;	//next state for the cypher portion of the BD
	logic clk_div;			 	//used to divide out the round counter, resulting in round + 1 every other clk cycle
	///////////////////////////

    //instantiation of states for the FSM
    parameter S0 = 3'b000; 		//initial state
	parameter KS1 = 2'b01; 	//rot_word -> STARTsub_bytes
	parameter KS2 = 2'b10; 	//ENDsub_bytes -> Rcon -> fill_round_key
	parameter CYPH1 = 2'b01; 	//ass_round_key -> STARTsub_bytes
	parameter CYPH2 = 2'b10; 	//ENDsub_bytes -> shift_rows -> mix_cols
    /////////////////////////////////////

    //next state logic (key schedule)/////////
    always_ff @(posedge clk)
		if (reset) 
			state_KS <= S0;
		else 	
			state_KS <= nextstate_KS;
	//////////////////////////////////////////

    //next state logic (cypher)///////////////
     always_ff @(posedge clk)
		if (reset) 
			state_CYPH <= S0;
		else 	
			state_CYPH <= nextstate_CYPH;
    //////////////////////////////////////////

    //FSM machines for (key schedule)///////////
    always_comb begin
        case(state_KS)
			S0:
				if (reset)					//wait for plain text to load before starting fsm loop
					nextstate_KS = S0;
				else
					nextstate_KS = KS1;
            KS1:
                nextstate_KS = KS2;
            KS2:
                nextstate_KS = KS1;
			default:
				nextstate_KS = S0;
        endcase
    end
	////////////////////////////////////////////
	
    //FSM machines for (key cypher)/////////////
    always_comb begin
        case(state_CYPH)
			S0:
				if (reset)					//wait for plain text to load before starting fsm loop
					nextstate_CYPH = S0;
				else
					nextstate_CYPH = CYPH1;
            KS1:
                nextstate_CYPH = CYPH2;
            KS2:
                nextstate_CYPH = CYPH1;
			default:
				nextstate_CYPH = S0;
        endcase
    end
	////////////////////////////////////////////

	// round counter ///////////////////////////
	always_ff @(posedge clk) begin
		if (reset)
			round = 0;
		else begin					//make sure that everything is loaded from MCU, and rounds have begun
			if (clk_div == 1) begin						//check every other clk cycle
				clk_div = 0;							//reset clk_div every other clk cycle
				if (round < 10) 						//round is never more than 10
					round = round + 4'b1;
			end else
				clk_div = 1'b1;							//clk_div = 1 every other clk cycle
		end
	end
	////////////////////////////////////////////
	
	// Register Logic **************************************************
	// - This will output triggers for a register control block in the top module to activate certain inputs to clock schedule, cypher, and add_round_key
	
	

	// round key register (2 input, one output) based on state and round
	//always_ff @(posedge clk) begin
		// Initialize output signals
		//rk_en = 1'b0;          // Default to 0
		//prev_rk_en = 1'b0;     // Default to 0
	always_comb begin
			case(state_KS)
				S0:
					rk_en = 2'b00;
				KS1: begin
					if(round != 0)														   //set previous round key = current rk in rot_word to store for use in rcon and fill_round_key
						rk_en = 2'b01;
					end
				KS2:																			//SWITCH THESE TWO//														   //set prev rk register to 0 in KS2 to store prev rk to be used in rcon and fill_round_key
					case(round)
						4'd0: rk_en = 2'b00;														   //input initial key to add_round_key for round 0 to produce initial intermediate_cypher
						4'd1, 4'd2, 4'd3, 4'd4, 4'd5, 4'd6, 4'd7, 4'd8, 4'd9, 4'd10: rk_en = 2'b01; //all future rounds, feed round_key calculated in key schedule, into add_round_key and rot_word
						default: rk_en = 2'b10;
					endcase
				default:
					rk_en = 2'b10;
			endcase
	end

	// prev_rk_en enabler mux
		always_comb begin
			case(state_KS)
				S0:
					prev_rk_en = 1'b0;
				KS1:
					prev_rk_en = 1'b1;															   //set previous round key = current rk in rot_word to store for use in rcon and fill_round_key
				KS2:																		//SWITCH THESE TWO//
					prev_rk_en = 1'b0;															   //set prev rk register to 0 in KS2 to store prev rk to be used in rcon and fill_round_key
				default:
					prev_rk_en = 1'b0;
			endcase
		end

	///////////////////////////////////////////////////////////////////
	
	// cyphertext source enable muxs
	always_comb begin
		if(state_CYPH == S0) begin
			case(round)
					4'd0: begin
						cyph_en = 3'b000;											 //round 0 feed plaintext into add_round_key to then calculate initial cyphertext
						init_cyph_en = 1'b1;
						end
					default: begin
						cyph_en = 3'b100;
						init_cyph_en = 1'b0;
						end
			endcase
		end
		else if(state_CYPH == KS1) begin
			case(round)
					4'd1: begin
						cyph_en = 3'b011;											 //feed intermediate_cypher from round 0 back into add_round_key
						init_cyph_en = 1'b0;
						end
					4'd2, 4'd3, 4'd4, 4'd5, 4'd6, 4'd7, 4'd8, 4'd9: begin
						cyph_en = 3'b001; 											 //rounds 2-9 feed calculated intermediate_cypher
						init_cyph_en = 1'b0;
						end
					4'd10: begin
						cyph_en = 3'b010;											 //final round hold final cyphertext on output pin awaiting "done" assertion
						init_cyph_en = 1'b0;
						end
					default: begin
						cyph_en = 3'b100;
						init_cyph_en = 1'b0;
						end
			endcase
		end

		else if(state_CYPH == KS2) begin
			case(round)
					4'd1: begin
						cyph_en = 3'b100;											 //feed intermediate_cypher from round 0 back into add_round_key
						init_cyph_en = 1'b0;
						end
					4'd2, 4'd3, 4'd4, 4'd5, 4'd6, 4'd7, 4'd8, 4'd9: begin
						cyph_en = 3'b100; 											 //rounds 2-9 feed calculated intermediate_cypher
						init_cyph_en = 1'b0;
						end
					4'd10: begin
						cyph_en = 3'b100;											 //final round hold final cyphertext on output pin awaiting "done" assertion
						init_cyph_en = 1'b0;
						end
					default: begin
						cyph_en = 3'b100;
						init_cyph_en = 1'b0;
						end
				
			endcase
		end
	end
	////////////////////////////////////////////////////////////////////
	//******************************************************************
	
	// done flag logic ////////
	
	
	always_ff @(posedge clk) begin
		case(round)
			4'd10:
				final_cyph_en = 1'b1;
			default:
				final_cyph_en = 1'b0;
		endcase
	end
	//////////////////////////
endmodule

// rot_word /////////////////////////////
// this is the first step to the key schedule process
/////////////////////////////////////////
module rot_word(
	input logic clk, reset,
	input logic [127:0] current_round_key,
	input logic prev_rk_en,
	output logic [127:0] prev_round_key,
	output logic [31:0] rot_word_done
	);
	
	// internal variables /////
	logic [31:0] w3;	//most right col in round key
	logic [7:0] B1;		//first byte from top in the col
	logic [7:0] B2;		//second byte from top in the col
	logic [7:0] B3;		//third byte from top in the col
	logic [7:0] B4;		//fourth byte from top in the col
	//////////////////////////
	
	// previous round key register ///////
	always_ff @(posedge clk) begin
		if (reset)
			prev_round_key <= 128'bx;
		else if (prev_rk_en)
			prev_round_key <= current_round_key;
	end
	//////////////////////////////////////
	
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
	input logic [127:0] prev_round_key,
	input logic [31:0] sub_bytes_done,
	input logic [3:0] round,
	output logic [31:0] rcon_done
	);
	
	// internal variables //
	logic [31:0] rcon[1:10] = '{ 32'h01000000,
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
        if (round >= 1 && round <= 10) begin								   //ensure in correct round bounds
            rcon_done = prev_round_key[127:96] ^ sub_bytes_done ^ rcon[round]; //XOR operation with the first word of previous RK, calculated sub_bytes word, and rcon value based on round
        end else begin
            rcon_done = 32'h00000000;
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
		fill_round_key_done[127:96] = rcon_done;											//set col[0] of new RK to be the majorly altered word from rcon and above
		fill_round_key_done[95:64] = prev_round_key[95:64] ^ fill_round_key_done[127:96];	//calculate col[1] based on prevRK col[1] and newRK col[0]
		fill_round_key_done[63:32] = prev_round_key[63:32] ^ fill_round_key_done[95:64];	//calculate col[2] based on prevRK col[2] and newRK col[1]
		fill_round_key_done[31:0] = prev_round_key[31:0] ^ fill_round_key_done[63:32];		//calculate col[3] based on prevRK col[3] and newRK col[2]
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
	input logic clk,
	input logic [127:0] cyphertext_intermediate,
	input logic [127:0] current_round_key,
	input logic init_cyph_en,
	output logic [127:0] cypher_zero,
	output logic [127:0] round_key_done
	);
	// add round key logic XOR cyphertext with current round key
	always_comb begin
		round_key_done <= cyphertext_intermediate ^ current_round_key;
	end
	////////////////////////////////////////////////////////////
	
	// initial add XOR round key register for round 0
	always_ff @(posedge clk) begin
		if (init_cyph_en)
			cypher_zero <= round_key_done;
		else
			cypher_zero <= cypher_zero;
	end
	/////////////////////////////////////////////////
endmodule

// sub bytes for the cypher /////////////////////////
// this is the second thing to do in the cypher side of the AES-128
/////////////////////////////////////////////////////
module sub_bytes_CYPH( //DO I NEED CLK AND RESET?
	input logic clk,
	input logic [127:0] round_key_done,
	output logic [127:0] sub_bytes_cypher_done
	);
	// perform sub bytes on full intermediate cypher with sbox_sync
	sbox_sync s4(round_key_done[7:0], clk, sub_bytes_cypher_done[7:0]);
	sbox_sync s5(round_key_done[15:8], clk, sub_bytes_cypher_done[15:8]);
	sbox_sync s6(round_key_done[23:16], clk, sub_bytes_cypher_done[23:16]);
	sbox_sync s7(round_key_done[31:24], clk, sub_bytes_cypher_done[31:24]);
	sbox_sync s8(round_key_done[39:32], clk, sub_bytes_cypher_done[39:32]);
	sbox_sync s9(round_key_done[47:40], clk, sub_bytes_cypher_done[47:40]);
	sbox_sync s10(round_key_done[55:48], clk, sub_bytes_cypher_done[55:48]);
	sbox_sync s11(round_key_done[63:56], clk, sub_bytes_cypher_done[63:56]);
	sbox_sync s12(round_key_done[71:64], clk, sub_bytes_cypher_done[71:64]);
	sbox_sync s13(round_key_done[79:72], clk, sub_bytes_cypher_done[79:72]);
	sbox_sync s14(round_key_done[87:80], clk, sub_bytes_cypher_done[87:80]);
	sbox_sync s15(round_key_done[95:88], clk, sub_bytes_cypher_done[95:88]);
	sbox_sync s16(round_key_done[103:96], clk, sub_bytes_cypher_done[103:96]);
	sbox_sync s17(round_key_done[111:104], clk, sub_bytes_cypher_done[111:104]);
	sbox_sync s18(round_key_done[119:112], clk, sub_bytes_cypher_done[119:112]);
	sbox_sync s19(round_key_done[127:120], clk, sub_bytes_cypher_done[127:120]);
	////////////////////////////////////////////////////////////
endmodule
//////////////////////////////////////////////////////

// shift rows/////////////////////////////////////////
// this works on shifiting the rows in the cypher section of the algorithm
//////////////////////////////////////////////////////
module shift_rows(
	input logic clk, final_cyph_en,
	input logic [127:0] sub_bytes_cypher_done,
	output logic [127:0] shift_rows_done,
	output logic [127:0] final_cypher_text
	);
	
	//internal variables
	logic [7:0] cypher_matrix[3:0][3:0];
	////////////////////
	
	// create cypher matrix to more easily shift rows /////////
	assign cypher_matrix[0][0] = sub_bytes_cypher_done[127:120];
	assign cypher_matrix[1][0] = sub_bytes_cypher_done[119:112];
	assign cypher_matrix[2][0] = sub_bytes_cypher_done[111:104];
	assign cypher_matrix[3][0] = sub_bytes_cypher_done[103:96];

	assign cypher_matrix[0][1] = sub_bytes_cypher_done[95:88];
	assign cypher_matrix[1][1] = sub_bytes_cypher_done[87:80];
	assign cypher_matrix[2][1] = sub_bytes_cypher_done[79:72];
	assign cypher_matrix[3][1] = sub_bytes_cypher_done[71:64];

	assign cypher_matrix[0][2] = sub_bytes_cypher_done[63:56];
	assign cypher_matrix[1][2] = sub_bytes_cypher_done[55:48];
	assign cypher_matrix[2][2] = sub_bytes_cypher_done[47:40];
	assign cypher_matrix[3][2] = sub_bytes_cypher_done[39:32];

	assign cypher_matrix[0][3] = sub_bytes_cypher_done[31:24];
	assign cypher_matrix[1][3] = sub_bytes_cypher_done[23:16];
	assign cypher_matrix[2][3] = sub_bytes_cypher_done[15:8];
	assign cypher_matrix[3][3] = sub_bytes_cypher_done[7:0];
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
	
	// final cypher storage register
	always_ff @(posedge clk) begin
		if(final_cyph_en)
			final_cypher_text = sub_bytes_cypher_done;
	end
	////////////////////////////////
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