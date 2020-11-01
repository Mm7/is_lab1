
class Feistel_Encr:

    #Initialization of the encryptor
    def __init__(self, len, rounds, pub_key):
        self.len = len
        self.rounds = rounds
        self.key = pub_key
        self.mask = 0x80000000

    #Function that updates the wi, remeber to shift everything to the right of 16 bits
    def round_function(self, round_in, sub_key):
        
        output = 0
        l = self.len // 2
        half_l = l // 2

        #First Half
        for j in range(1, half_l + 1):
            #tmp variables in order to make everything more clear

            #Shift to the right most position if it is no already in that position
            mex_target_bit = round_in << ( j - 1 )  
            key_target_bit = sub_key << ( 4 * j - 4 )
            
            #use a mask to get only the bit needed 
            bit_j = ( mex_target_bit ^ key_target_bit ) & self.mask 

            #Put the bit back in the correct position
            bit_mask_j = bit_j >> ( j - 1 )
            
            #Do the or with the output in order to save the bits
            output |= bit_mask_j 

        #Second Half
        for j in range(half_l + 1, l + 1):
            #tmp variables in order to make everything more clear

            #Shift to the left most position if it is no already in that position
            mex_target_bit = round_in << ( j - 1 ) 
            key_target_bit = sub_key << ((2 * j - l) * 2 - 1 )
            
            #use a mask to get only the bit needed 
            bit_j = ( mex_target_bit ^ key_target_bit ) & self.mask 

            #Put the bit back in the correct position
            bit_mask_j = bit_j >> ( j - 1 )
            
            #Do the or with the output in order to save the bits
            output |= bit_mask_j 

        return output


    #Function that generates the subkey for the i-eth round --- Correct !
    def sub_key_gen(self, round_ith):
        
        sub_key = 0 
        for j in range(1, self.len + 1):
            
            #Should be -1 but we start from zero so subtract one
            key_index =  ( 5 * round_ith + j - 1 ) % self.len # + 1 - 1

            #Shift to the first position the bit and extract it using the max
            bit_j = ( self.key << key_index ) & self.mask

            #Putting in the postion that I want to 
            bit_mask_j = bit_j >> ( j - 1 )

            #Save the bit in the new subkey
            sub_key |= bit_mask_j
        

        return sub_key


    #Encryption Method
    def encryption(self, message_u):
        
        #Divide in two halves the message -- 
        y = ( message_u & 0xFFFF0000 )  
        z = ( message_u & 0x0000FFFF ) << 16

        for i in range(1, self.rounds + 1):

            #Substitution  
            sub_key = self.sub_key_gen(i)
            w = self.round_function(y, sub_key)

            #Linear tranformation 
            v = z ^ w  

            #Transposition 
            if ( i < self.rounds ):
                z = y
                y = v
            else : # The last round doesnt switch 
                z = v

        #Concatenation of the message
        message_x = (z >> 16) | y 

        return message_x



