import f_cipher as ciph
import numpy as np

class Linear_Attack:

    def __init__(self, len_u, len_x, len_k):
        #Len of the key/message ecc ecc
        self.len_u = len_u
        self.len_x = len_x
        self.len_k = len_k

    
    #Transforms bit arrays in vectors to use for calculations
    def vectorize_bits(self, bites, len):

        #Final vector
        vec = np.zeros(len)
        #Initial Mask
        mask = 0x1

        #If there is a one in that position I will insert it in the array
        for i in range(len):
            bit_i = ( bites >> len - i - 1) & mask
            if ( bit_i ) : vec[i] = 1

        #It is a row vector
        return vec


    #Transforms vectors of bits in numbers
    def bitization(self, vec):

        result = 0
        #Classic algorithm for this calc
        for i in range(len(vec)):
            if ( vec[i] ) : result += 2 ** ( len(vec) - 1 - i)

        return result
    
    
    def find_B_matrix(self, n_rounds):
        
        #Elements needed
        cipher = ciph.Feistel(self.len_k, n_rounds, 0x0)
        u = 0x80000000
        B = np.zeros((self.len_x, self.len_u))        

        for i in range(self.len_u):
            #Let's shift until we do all the versors
            ui = u >> i
            xi_vec = self.vectorize_bits(cipher.encryption(ui), self.len_x)
            B[:, i] = xi_vec[:]

        return B

    
    def find_A_matrix(self, n_rounds):

        #Elements needed
        key = 0x80000000
        A = np.zeros((self.len_x, self.len_k))        

        for i in range(self.len_k):
            #Let's shift until we do all the versors
            key_i = key >> i 
            cipher = ciph.Feistel(self.len_k, n_rounds, key_i)

            xi_vec = self.vectorize_bits(cipher.encryption(0x0), self.len_x)
            A[:, i] = xi_vec[:]


        return A

    
    def extract_key(self, n_rounds, message_x, message_u):

        #Just solving a linear system
        key = 0 
        A = self.find_A_matrix(n_rounds)
        B = self.find_B_matrix(n_rounds)

        A_inv = ( np.linalg.inv(A) * np.linalg.det(A) ) 
           
        A = self.round_mat(A)
        A_inv = self.round_mat(A_inv) % 2
        B = self.round_mat(B)   

        u_vec = self.round_vec(self.vectorize_bits(message_u, self.len_u).transpose() )
        x_vec = self.round_vec(self.vectorize_bits(message_x, self.len_x).transpose() )

        w = self.vec_sum(x_vec, self.mat_vec_prod(B, u_vec))
        key = self.mat_vec_prod(A_inv, w)

        return self.bitization(key)


    def vec_sum(self, vec1, vec2 ):

        result = np.zeros(len(vec1), dtype=int)
        for index in range(len(vec1)):
            result[index] = vec1[index] ^ vec2[index]
        
        return result

    def vec_prod(self, vec1, vec2 ):

        result = 0 
        for index in range(len(vec1)):
            result ^= vec1[index] & vec2[index]

        return result

    
    def mat_vec_prod(self, mat, vec2):

        result = np.zeros(mat.shape[0], dtype=int)
        for index in range(len(mat)):
            result[index] = self.vec_prod(mat[index, :], vec2)

        return result

    def mat_mat_prod(self, mat1, mat2):

        result = np.zeros(mat1.shape, dtype=int)

        for i in range(mat2.shape[1]):
            result[:, i] = self.mat_vec_prod(mat1, mat2[:, i])[:]

        return result


    def round_mat(self, mat):

        tmp_mat = np.zeros(mat.shape, dtype=int)
        for i in range(mat.shape[0]):
            for j in range(mat.shape[1]):
                tmp_mat[i, j] = round(mat[i, j])
        return tmp_mat

    def round_vec(self, vec):
        
        tmp_vec = np.zeros(len(vec), dtype=int)
        for i in range(len(vec)):
            tmp_vec[i] = round(vec[i])

        return tmp_vec