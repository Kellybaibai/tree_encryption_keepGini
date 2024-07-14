'''
Descripttion: The experiment to compare the security through the bitwise leakage matrix.
version: v1
Author: anonymous
'''

import numpy as np
import math
import seaborn as sns
import matplotlib.pyplot as plt
from collections import Counter

#Get all data with the j-th bit being b
def get_bitData(data, j, b):  
    """
        Parameters
        ----------
        data : list 
            The auxiliary dataset own by the adversary.
        j : int
            The j-th bit.
        b : int
            Value of 0/1. 
    """
    ans = []
    for i in range(len(data)):
        if (format(data[i], "b").zfill(7)[j] == b):
            ans.append(data[i])
    return ans

#Get the probability of pr[x(i)=s], reference pape: Strengthening Order Preserving Encryption with Differential Privacy.
def getPro(data, i_rank, s, CDF_index, CDF_value):  
    smallPro = 0
    s_index = CDF_index.index(s)
    if (s_index - 1 >= 0):
        smallPro = CDF_value[s_index - 1]
    equalPro = CDF_value[s_index] - smallPro
    bigPro = 1 - smallPro - equalPro  
    i_rank += 1

    ans = 0
    if (bigPro == 0):
        for j in range(len(data) - i_rank + 1, len(data) + 1):
            ans = ans + (math.factorial(len(data)) //
                         (math.factorial(j) * math.factorial(len(data) - j))
                         ) * math.pow(smallPro,
                                      len(data) - j) * math.pow(equalPro, j)
       
    elif (smallPro == 0):
        for j in range(i_rank, len(data) + 1):
            ans = ans + (math.factorial(len(data)) //
                         (math.factorial(j) * math.factorial(len(data) - j))
                         ) * math.pow(bigPro,
                                      len(data) - j) * math.pow(equalPro, j)
         
    else:
        for j in range(1, len(data) + 1):
            k_left = max(1, i_rank - j + 1)
            k_right = min(i_rank, len(data) - j + 1)
            for k in range(k_left, k_right + 1):
                tmp = (
                    math.factorial(len(data)) //
                    (math.factorial(k - 1) *
                     math.factorial(len(data) - k - j + 1) * math.factorial(j))
                ) * math.pow(smallPro, k - 1) * math.pow(
                    equalPro, j) * math.pow(bigPro,
                                            len(data) - k - j + 1)
                ans += tmp
    return ans

# Get the bitwise leakage matrix for OPE according to the paper: Strengthening Order Preserving Encryption with Differential Privacy
def Leakage_Matrix(Original_D, Ouxiliary_D, CDF_index,
                   CDF_value):   
    L = [ ]  

    for i in range(len(Original_D)):
        tmp_L = []
        print(i)
        for j in range(7):  #Set the bit to [0,6]
            b = format(Ouxiliary_D[i],"b").zfill(7)[j]  #Guess b (0/1) according to the additional information obtained by the attacker
            s_Data = get_bitData(Original_D, j, b)
            Pr = 0  #Get the probability of pr[x(i)=s]
            for s in set(s_Data):
                Pr += getPro(Original_D, i, s, CDF_index, CDF_value)
            print(Pr)
            tmp_L.append(Pr)
        L.append(tmp_L)
    return L

# Get the bitwise leakage matrix for our GIPE according to the paper: Strengthening Order Preserving Encryption with Differential Privacy
def Leakage_MatrixCipher(Original_D, Ouxiliary_D, CDF_index, CDF_value,
                         cipher):   
    L = []

    for i in range(len(Original_D)):
        print(i)
        cipgerI = cipher[i]
        #All plaintext corresponding to the i-th ciphertext
        indexCipherI = [i for i, x in enumerate(cipher) if x == cipgerI]
        plaintexts = [Original_D[i] for i in indexCipherI]
        plainI = Original_D[i]

        tmp_L = []
        for j in range(7):  #Set the bit to [0,6]
            plaintexts_b = []
            for item in plaintexts:
                plaintexts_b.append(format(item, "b").zfill(7)[j])#Guess b (0/1) according to the additional information obtained by the attacker
            dict_count = Counter(plaintexts_b)
            proba = dict_count[format(plainI,"b").zfill(7)[j]] / len(plaintexts_b) #Get the probability of guessing correctly the ciphertext corresponding plaintext 

            b = format(Ouxiliary_D[i],
                       "b").zfill(7)[j]  
            s_Data = get_bitData(Original_D, j, b)
            Pr = 0  #Get the probability of pr[x(i)=s]
            for s in set(s_Data):
                Pr += getPro(Original_D, i, s, CDF_index, CDF_value)
            Pr *= proba
            print(Pr)
            tmp_L.append(Pr)
        L.append(tmp_L)
    return L

#Get the  cumulative distribution function of data.
def get_CDF(data):
    CDF = {}
    CDF_index = []
    CDF_value = []
    for item in set(data):
        CDF_index.append(item)
        num = 0
        for i in range(len(data)):
            if (data[i] <= item):
                num += 1
        CDF[item] = num / len(data)
        CDF_value.append(num / len(data))
    return CDF, CDF_index, CDF_value

#Draw the bitwise leakage matrix heatmap
def draw_heatmap(L, url):
    sns.set_style('white')
    x_ticks = ['1', '2', '3', '4', '5', '6', '7']
    y_ticks = [""]
    for i in range(len(L)):
        for j in range(len(L.iloc[0, :])):
            if (L.iloc[i][j] < 0.5):
                L.iloc[i][j] = 0.5 + np.random.rand() * 0.1
    data = L
    sns.set(font_scale=2.5)
    cmap = sns.cubehelix_palette(rot=0.5,
                                 hue=2,
                                 n_colors=200,
                                 dark=0.45,
                                 light=0.9,
                                 gamma=0.5)
    ax = sns.heatmap(data,
                     xticklabels=x_ticks,
                     yticklabels=40,
                     vmax=1.2,
                     vmin=0,
                     cmap="OrRd")
    ax.set_xlabel('Bit', fontsize=20)  
    ax.set_ylabel('Rank', fontsize=20)
    plt.show()
    plt.figure()
    return
