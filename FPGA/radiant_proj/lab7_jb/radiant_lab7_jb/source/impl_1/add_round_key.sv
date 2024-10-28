// Jason Bowman
// jbowman@hmc.edu
// CREATED: 10-28-24
// This module acts as the add round key part of AES, using XOR with the appropriate input depending on the round and throwing a flag once each round has been completed

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
		endcase
	end

endmodule